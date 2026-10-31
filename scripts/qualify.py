#!/usr/bin/env python3
"""Run an explicit local interpreter matrix without changing hosted workflows."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", action="append", dest="interpreters", default=[])
    parser.add_argument("--powershell")
    parser.add_argument("--transactions", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build/qualification")
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"platform": platform.system(), "arch": platform.machine(), "scope": "local-runtime-matrix", "runs": [],
              "live_enclave": "not_used", "windows_guest": "not_verified", "rdpdr": "not_verified", "vendor_keys": "not_used"}
    source_files = [path for folder in ("src", "scripts", "tests", "native") for path in (ROOT / folder).rglob("*")
                    if path.is_file() and path.suffix in (".py", ".ps1", ".cs", ".csproj")
                    and not any(part in ("obj", "bin", "__pycache__") for part in path.parts)]
    report["source_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(source_files)}
    commands = []
    for executable in args.interpreters or [sys.executable]:
        version = subprocess.check_output([executable, "-c", "import sys;print(sys.version.split()[0])"], text=True).strip()
        commands.append(("python-" + version, [executable, "-m", "unittest", "discover", "-s", "tests", "-v"]))
    commands.append(("hygiene", [sys.executable, "scripts/verify_hygiene.py"]))
    if args.powershell:
        commands.append(("worker-loopback", [sys.executable, "scripts/qualification/worker_loopback.py", "--powershell", args.powershell,
                                              "--transactions", str(args.transactions), "--output", str(args.output_dir / "worker.json")]))
    environment = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    for label, command in commands:
        log = args.output_dir / (label + ".log")
        started = time.monotonic()
        with log.open("wb") as output:
            try:
                process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT,
                                           start_new_session=(os.name != "nt"))
                process.wait(timeout=args.timeout)
                status = "passed" if process.returncode == 0 else "failed"
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=output, stderr=subprocess.STDOUT, timeout=10)
                else:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                process.wait(timeout=10)
                status = "timed_out"
        row = {"name": label, "status": status, "elapsed_sec": round(time.monotonic()-started, 3), "log": log.name,
               "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        report["runs"].append(row)
        print(f"{label}: {status}", flush=True)
    report["status"] = "passed" if all(row["status"] == "passed" for row in report["runs"]) else "failed"
    (args.output_dir / "matrix.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
