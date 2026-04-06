#!/usr/bin/env python3
"""Simple file scanner wrapper around ClamAV (clamd or clamscan).

Usage examples:
  python antivirus_scanner.py /path/to/file
  python antivirus_scanner.py /path/to/folder --recursive
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


class ScanResult:
    def __init__(self, target: Path, status: str, details: str = "") -> None:
        self.target = target
        self.status = status
        self.details = details

    @property
    def infected(self) -> bool:
        return self.status.upper() == "FOUND"


class ClamAVScanner:
    """Scan files using clamd first, then fallback to clamscan."""

    def __init__(self) -> None:
        self._clamd = None

    def _connect_clamd(self):
        if self._clamd is not None:
            return self._clamd

        try:
            import pyclamd  # type: ignore
        except Exception:
            self._clamd = False
            return None

        # Try local UNIX socket first, then TCP default.
        for connector in (pyclamd.ClamdUnixSocket, pyclamd.ClamdNetworkSocket):
            try:
                client = connector()
                client.ping()
                self._clamd = client
                return client
            except Exception:
                continue

        self._clamd = False
        return None

    def scan_file(self, path: Path) -> ScanResult:
        clamd_client = self._connect_clamd()
        if clamd_client:
            try:
                result = clamd_client.scan_file(str(path))
                if not result:
                    return ScanResult(path, "OK")

                _, (status, signature) = next(iter(result.items()))
                return ScanResult(path, status, signature or "")
            except Exception as exc:
                return ScanResult(path, "ERROR", f"clamd scan failed: {exc}")

        clamscan_bin = shutil.which("clamscan")
        if not clamscan_bin:
            return ScanResult(
                path,
                "ERROR",
                "No ClamAV engine found. Install clamscan or `pip install pyclamd` and run clamd.",
            )

        proc = subprocess.run(
            [clamscan_bin, "--no-summary", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        if proc.returncode == 0:
            return ScanResult(path, "OK")
        if proc.returncode == 1:
            line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
            # Example: /tmp/eicar.com: Eicar-Signature FOUND
            details = line.split(":", 1)[-1].replace("FOUND", "").strip()
            return ScanResult(path, "FOUND", details)

        details = (proc.stderr or proc.stdout or "Unknown error").strip()
        return ScanResult(path, "ERROR", details)


def iter_files(target: Path, recursive: bool) -> Iterable[Path]:
    if target.is_file():
        yield target
        return

    pattern = "**/*" if recursive else "*"
    for item in target.glob(pattern):
        if item.is_file():
            yield item


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan files for malware using ClamAV.")
    parser.add_argument("target", type=Path, help="File or directory to scan")
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="When target is a directory, scan subdirectories recursively.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    target: Path = args.target.expanduser().resolve()

    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 2

    scanner = ClamAVScanner()
    results = [scanner.scan_file(path) for path in iter_files(target, args.recursive)]

    if not results:
        print(f"No files found to scan in: {target}")
        return 0

    infected = 0
    errors = 0

    for result in results:
        if result.status == "OK":
            print(f"[OK] {result.target}")
        elif result.status == "FOUND":
            infected += 1
            details = f" ({result.details})" if result.details else ""
            print(f"[INFECTED] {result.target}{details}")
        else:
            errors += 1
            print(f"[ERROR] {result.target}: {result.details}")

    print("\nSummary")
    print(f"  Files scanned: {len(results)}")
    print(f"  Infected:      {infected}")
    print(f"  Errors:        {errors}")

    if infected > 0:
        return 1
    if errors > 0:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
