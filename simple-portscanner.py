#!/usr/bin/env python3

import argparse
import socket
import logging
import json
import csv
import pathlib
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

LOG = logging.getLogger(__name__)


def parse_ports(range_str: str | None = None, ports_str: str | None = None) -> List[int]:
    ports = set()
    if range_str is not None:
        try:
            start, end = map(int, range_str.split("-"))
        except ValueError:
            raise ValueError("Invalid range format, expected START-END (e.g. 20-1024)")
        if start > end:
            start, end = end, start
        ports.update(range(start, end + 1))
    if ports_str is not None:
        for part in ports_str.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid port number: {part!r}")
    if not ports:
        raise ValueError("No ports specified")
    return sorted(ports)


def _resolve_host(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = []
        seen = set()
        for info in infos:
            family = info[0]
            addr = info[4][0]
            key = (family, addr)
            if key in seen:
                continue
            seen.add(key)
            addrs.append((family, addr))
        if not addrs:
            raise ValueError(f"No addresses found for host '{host}'")
        return addrs
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host '{host}': {e}")


def scan_port(addrs, port, timeout: float) -> bool:
    for family, addr in addrs:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if family == socket.AF_INET6:
                    sockaddr = (addr, port, 0, 0)
                else:
                    sockaddr = (addr, port)
                result = s.connect_ex(sockaddr)
                if result == 0:
                    return True
        except OSError as e:
            LOG.debug("connect to %s (family %s) port %d failed: %s", addr, family, port, e)
            continue
    return False


def scan_ports(host: str, ports: List[int], timeout: float = 0.5, threads: int = 10):
    addrs = _resolve_host(host)
    open_ports = []
    total = len(ports)
    LOG.info("Scanning %s %s %d ports with timeout=%ss using %d threads", host, addrs, total, timeout, threads)

    try:
        from tqdm import tqdm
    except ImportError:
        LOG.debug("tqdm not installed; progress bar disabled")
        tqdm = None

    with ThreadPoolExecutor(max_workers=threads) as exe:
        future_to_port = {exe.submit(scan_port, addrs, port, timeout): port for port in ports}
        try:
            iterator = as_completed(future_to_port)
            if tqdm:
                iterator = tqdm(iterator, total=total, desc=f"Scanning {host}")

            for future in iterator:
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                        LOG.debug("Port %d is open", port)
                except Exception as e:
                    LOG.error("Error scanning port %d: %s", port, e)
        except KeyboardInterrupt:
            LOG.warning("Keyboard interrupt received, shutting down executor...")
            exe.shutdown(wait=False)
            raise

    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(description="Simple concurrent TCP port scanner")
    parser.add_argument("--host", required=True, help="Target host (IP or hostname)")
    parser.add_argument("--range", help="Port range, e.g. 20-1024")
    parser.add_argument("--ports", help="Comma-separated ports, e.g. 22,80,443")
    parser.add_argument("--timeout", type=float, default=0.5, help="Connect timeout in seconds (default: 0.5)")
    parser.add_argument("--threads", type=int, default=10, help="Number of worker threads (default: 10)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--format", choices=("plain", "json", "csv"), default="plain", help="Output format (default: plain)")
    parser.add_argument("--output-file", help="Write results to given file (path). Format inferred from --format if provided.")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    try:
        ports = parse_ports(args.range, args.ports)
    except ValueError as e:
        parser.error(str(e))

    try:
        open_ports = scan_ports(args.host, ports, timeout=args.timeout, threads=args.threads)
    except ValueError as e:
        LOG.error(e)
        return 1
    except KeyboardInterrupt:
        LOG.info("Scan interrupted by user")
        return 2

    out_text = ""
    if args.format == "plain":
        if open_ports:
            out_text = f"Open ports on {args.host}: {open_ports}"
        else:
            out_text = f"No open ports found on {args.host} in the specified set."
        print(out_text)
    elif args.format == "json":
        out_obj = {"host": args.host, "open_ports": open_ports}
        out_text = json.dumps(out_obj)
        print(out_text)
    elif args.format == "csv":
        if open_ports:
            out_lines = ["host,port"] + [f"{args.host},{p}" for p in open_ports]
            out_text = "\n".join(out_lines)
        else:
            out_text = "host,port"
        print(out_text)

    if args.output_file:
        out_path = pathlib.Path(args.output_file)
        try:
            if str(out_path.parent) != ".":
                out_path.parent.mkdir(parents=True, exist_ok=True)

            if args.format == "json":
                try:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        json.dump({"host": args.host, "open_ports": open_ports}, fh, indent=2)
                except TypeError as e:
                    LOG.error("Failed to serialize results to JSON: %s", e)
                    return 1
            elif args.format == "csv":
                try:
                    with open(out_path, "w", newline="", encoding="utf-8") as fh:
                        writer = csv.writer(fh)
                        writer.writerow(["host", "port"])
                        for p in open_ports:
                            writer.writerow([args.host, p])
                except (OSError, TypeError) as e:
                    LOG.exception("Error while writing CSV to %s: %s", args.output_file, e)
                    return 1
            else:
                tmp = None
                try:
                    temp_dir = out_path.parent or "."
                    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=temp_dir) as tmpf:
                        tmpf.write(out_text + "\n")
                        tmp = tmpf.name
                    os.replace(tmp, out_path)
                except OSError as e:
                    LOG.exception("Filesystem error while writing %s", args.output_file)
                    if tmp:
                        try:
                            os.remove(tmp)
                        except OSError:
                            LOG.debug("Failed to remove temp file %s", tmp)
                    return 1
            LOG.info("Wrote results to %s", args.output_file)
        except OSError as e:
            LOG.exception("Filesystem error while preparing to write %s", args.output_file)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
