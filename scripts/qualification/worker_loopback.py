#!/usr/bin/env python3
"""Exercise the real worker using only disposable files and loopback sockets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from enclave_gateway.config import BastionSpec
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport


class FileChannel:
    supports_direct_spool_ipc = True

    def __init__(self, spool: Path, powershell: str):
        self.spool, self.powershell = spool, powershell

    def path(self, value):
        name = str(value).replace("\\", "/").rsplit("/", 1)[-1]
        if name in ("", ".", ".."):
            raise ValueError("Invalid fixture filename")
        return self.spool / name

    def publish_bytes(self, data, path):
        target = self.path(path)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(target)

    def write_bytes(self, data, path): self.path(path).write_bytes(data)
    def read_bytes(self, path): return self.path(path).read_bytes()
    def write_file(self, source, path): self.write_bytes(Path(source).read_bytes(), path)
    def read_file(self, path, target): Path(target).write_bytes(self.read_bytes(path))
    def consume_file(self, path): self.path(path).unlink(missing_ok=True)

    def try_read_bytes(self, path, **_kwargs):
        try: return self.read_bytes(path) or None
        except FileNotFoundError: return None

    def exec_powershell(self, script, timeout_sec=120):
        # This adapter is fixture-only. It never connects to a configured VM.
        if os.name != "nt":
            script = script.replace("\\", "/")
        encoded = base64.b64encode(script.encode("utf-16le")).decode()
        result = subprocess.run([self.powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, timeout=timeout_sec)
        return ExecResult(result.returncode, result.stdout.decode("utf-8", "replace"), result.stderr.decode("utf-8", "replace"), 0)


class EchoServer:
    def __init__(self, *, silent=False):
        self.silent = silent
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(16)
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.clients = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try: client, _ = self.socket.accept()
            except socket.timeout: continue
            except OSError: break
            self.clients.append(client)
            threading.Thread(target=self.echo, args=(client,), daemon=True).start()

    def echo(self, client):
        client.settimeout(0.1)
        try:
            while not self.stop.is_set():
                try: data = client.recv(65536)
                except socket.timeout: continue
                if not data:
                    if not self.silent:
                        time.sleep(0.05)
                        client.sendall(b"after-eof")
                    break
                if not self.silent: client.sendall(data)
        except OSError: pass
        finally: client.close()

    def close(self):
        self.stop.set()
        self.socket.close()
        for client in self.clients:
            try: client.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        self.thread.join(2)


class Worker:
    def __init__(self, powershell: str, directory: Path):
        self.powershell, self.directory = powershell, directory
        self.spool = directory / "spool"
        self.spool.mkdir(exist_ok=True)
        self.stop_file = directory / "stop"
        self.output = None
        self.process = None
        self.transport = RdpVfsTransport(FileChannel(self.spool, powershell), BastionSpec(
            appliance_spool_dir=str(self.spool), bastion_spool_dir=str(self.spool), block_size_bytes=65536, parallel_streams=2))

    def start(self):
        self.stop_file.unlink(missing_ok=True)
        (self.spool / "worker_state.json").unlink(missing_ok=True)
        self.output = (self.directory / "worker.log").open("ab")
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("ENCLAVE_", "EGW_", "SSH_"))}
        self.process = subprocess.Popen([self.powershell, "-NoProfile", "-NonInteractive", "-File",
            str(ROOT / "src/enclave_gateway/agents/bastion_worker.ps1"), "-SpoolDir", str(self.spool),
            "-StopFile", str(self.stop_file), "-PollIntervalMs", "2"], stdout=self.output, stderr=self.output, env=environment)
        deadline = time.monotonic() + 15
        while not (self.spool / "worker_state.json").exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                self.close()
                raise RuntimeError((self.directory / "worker.log").read_text(errors="replace"))
            time.sleep(0.02)
        return self

    def close(self):
        if self.process is not None:
            self.stop_file.write_text("stop")
            try: self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(5)
            self.process = None
        if self.output:
            self.output.close(); self.output = None

    def raw(self, tx_id, script, timeout_ms=5000):
        envelope = {"tx_id": tx_id, "op": "exec", "timeout_ms": timeout_ms,
                    "payload_b64": base64.b64encode(script.encode()).decode()}
        return self.transport._dispatch_envelope(envelope, timeout_sec=6)


def run(powershell: str, transactions: int = 100):
    findings = {"scope": "isolated-files-and-loopback", "platform": sys.platform, "transactions": transactions,
                "worker_sha256": hashlib.sha256((ROOT / "src/enclave_gateway/agents/bastion_worker.ps1").read_bytes()).hexdigest()}
    with TemporaryDirectory(prefix="egw-worker-") as temporary:
        root = Path(temporary)
        worker = Worker(powershell, root)
        fast, slow = EchoServer(), EchoServer(silent=True)
        try:
            worker.start()
            response = worker.raw("tx_basic", "Write-Output 'fixture-ok'")
            assert response.exit_code == 0 and response.stdout == "fixture-ok", response
            transport = worker.transport
            first = transport.mux_open("127.0.0.1", fast.port)
            blocked = transport.mux_open("127.0.0.1", slow.port)
            with ThreadPoolExecutor(max_workers=2) as pool:
                waiting = pool.submit(transport.mux_io, blocked, b"silent", read_wait_ms=1000)
                time.sleep(0.05)
                started = time.monotonic()
                echoed, eof = transport.mux_io(first, b"binary\0\xff", read_wait_ms=100)
                elapsed = time.monotonic() - started
                assert echoed == b"binary\0\xff" and not eof, (echoed, eof)
                assert elapsed < 0.8, elapsed
                assert waiting.result()[0] == b""
                findings["fast_io_during_slow_read_ms"] = round(elapsed * 1000)
            transport.mux_shutdown_write(first)
            collected, eof = b"", False
            for _ in range(20):
                data, eof = transport.mux_io(first, read_wait_ms=100)
                collected += data
                if eof: break
            assert eof and collected == b"after-eof", (collected, eof)
            transport.mux_close(first); transport.mux_close(blocked)
            for size in (0, 65536, 131072, 131073):
                source = root / "исходный файл.bin"
                destination = root / "папка ' с пробелом.bin"
                retrieved = root / "retrieved.bin"
                payload = (bytes(range(256)) * 513)[:size]
                source.write_bytes(payload)
                expected = hashlib.sha256(payload).hexdigest()
                assert transport.push_file(source, str(destination)) == expected
                assert transport.pull_file(str(destination), retrieved) == expected
                assert retrieved.read_bytes() == payload
            marker = root / "executions"
            script = "[IO.File]::AppendAllText(" + ps_quote(str(marker)) + ", 'x'); Write-Output 'once'"
            assert worker.raw("tx_durable", script).exit_code == 0
            worker.close(); worker.start()
            replay = worker.raw("tx_durable", script)
            assert marker.read_text() == "x", "Request replayed after restart"
            assert replay.exit_code == 125, replay
            with ThreadPoolExecutor(max_workers=2) as pool:
                running = pool.submit(worker.raw, "tx_cancel", "Start-Sleep -Seconds 30")
                time.sleep(0.2)
                transport.request_cancel("tx_cancel")
                cancelled = running.result(timeout=5)
                assert cancelled.exit_code == 125, cancelled
            # Malformed input and a refused connection must leave the dispatcher usable.
            (worker.spool / 'req_malformed.json').write_text('{invalid')
            refused = socket.socket(); refused.bind(('127.0.0.1', 0))
            refused_port = refused.getsockname()[1]; refused.close()
            try:
                transport.mux_open('127.0.0.1', refused_port, timeout_sec=2)
                raise AssertionError('Refused connection reported success')
            except ConnectionError:
                pass
            timed_out = worker.raw('tx_remote_timeout', 'Start-Sleep -Seconds 30', timeout_ms=100)
            assert timed_out.exit_code == 125, timed_out
            assert worker.raw('tx_after_errors', "Write-Output 'alive'").stdout == 'alive'
            samples = []
            def execute(index):
                result = transport.exec_bastion("Write-Output 'soak-ok'", timeout_sec=10)
                assert result.exit_code == 0 and result.stdout == "soak-ok", result
                if index % 100 == 0:
                    try: samples.append(json.loads((worker.spool / "worker_state.json").read_text()))
                    except (ValueError, OSError): pass
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(execute, range(transactions)))
            findings["elapsed_sec"] = round(time.monotonic() - started, 3)
            time.sleep(2.1)
            final = json.loads((worker.spool / "worker_state.json").read_text())
            samples.append(final)
            findings["resource_samples"] = samples
            findings["handles_supported"] = os.name == "nt"
            findings["resource_acceptance"] = "sampled bounds, not proof of indefinite leak freedom"
            warm = [sample for sample in samples if sample.get('completed_transactions', 0) >= 1000]
            if transactions >= 2000:
                assert len(warm) >= 2, 'Insufficient post-warmup samples'
                memory_growth = max(row['working_set_bytes'] for row in warm)-warm[0]['working_set_bytes']
                thread_growth = max(row['threads'] for row in warm)-warm[0]['threads']
                assert memory_growth <= 256*1024*1024, memory_growth
                assert thread_growth <= 64, thread_growth
                findings['post_warmup_memory_growth_bytes'] = memory_growth
                findings['post_warmup_thread_growth'] = thread_growth
                if os.name == 'nt':
                    handle_growth = max(row['handles'] for row in warm)-warm[0]['handles']
                    assert handle_growth <= 64, handle_growth
                    findings['post_warmup_handle_growth'] = handle_growth
            assert final['active_tx_jobs'] == 0 and final['pending_mux'] == 0 and final['active_mux_streams'] == 0, final
            findings["checks"] = ["script-execution", "mux-fairness", "binary-io", "half-close", "striped-files", "restart-no-replay", "cancellation", "remote-timeout", "malformed-envelope", "refused-connect", "soak"]
            findings["status"] = "passed"
        finally:
            worker.close(); fast.close(); slow.close()
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--powershell", default=shutil.which("pwsh") or shutil.which("powershell"))
    parser.add_argument("--transactions", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.powershell: parser.error("A PowerShell executable is required")
    if not 1 <= args.transactions <= 100000: parser.error("transactions must be in 1..100000")
    result = run(args.powershell, args.transactions)
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
