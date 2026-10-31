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
from enclave_gateway.control.published import read_shared
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
        from enclave_gateway.control.published import try_read_published
        return try_read_published(self.path(path))

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
    def __init__(self, powershell: str, directory: Path, runtime=None, allow_unsigned_lab=False, trusted_signer=''):
        self.powershell, self.directory = powershell, directory
        self.runtime,self.allow_unsigned_lab=runtime,allow_unsigned_lab
        self.trusted_signer=trusted_signer
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
        command=[self.powershell, "-NoProfile", "-NonInteractive", "-File",
            str(ROOT / "src/enclave_gateway/agents/bastion_worker.ps1"), "-SpoolDir", str(self.spool),
            "-StopFile", str(self.stop_file), "-PollIntervalMs", "2", "-Diagnostics"]
        if self.runtime: command+=['-RuntimeHelper',str(self.runtime)]
        if self.allow_unsigned_lab: command+=['-AllowUnsignedLab']
        if self.trusted_signer: command+=['-TrustedSignerThumbprints',self.trusted_signer]
        self.process = subprocess.Popen(command, stdout=self.output, stderr=self.output, env=environment)
        deadline = time.monotonic() + 15
        while not (self.spool / "worker_state.json").exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                self.close()
                raise RuntimeError((self.directory / "worker.log").read_text(errors="replace"))
            time.sleep(0.02)
        self.transport._verified_worker=None;self.transport._verified_until=0
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

    def raw(self, tx_id, script, timeout_ms=15000):
        envelope = {"tx_id": tx_id, "op": "exec", "timeout_ms": timeout_ms,
                    "payload_b64": base64.b64encode(script.encode()).decode()}
        return self.transport._dispatch_envelope(envelope, timeout_sec=max(6,timeout_ms/1000+1))


def run(powershell: str, transactions: int = 100, runtime=None, allow_unsigned_lab=False, trusted_signer='',exec_every=1,evidence_directory=None):
    findings = {"scope": "isolated-files-and-loopback", "platform": sys.platform, "transactions": transactions,
                "worker_sha256": hashlib.sha256((ROOT / "src/enclave_gateway/agents/bastion_worker.ps1").read_bytes()).hexdigest()}
    with TemporaryDirectory(prefix="egw-worker-") as temporary:
        root = Path(temporary)
        worker = Worker(powershell, root, runtime, allow_unsigned_lab,trusted_signer)
        fast, slow = EchoServer(), EchoServer(silent=True)
        try:
            worker.start()
            response = worker.raw("tx_basic", "Write-Output 'fixture-ok'")
            assert response.exit_code == 0 and response.stdout == "fixture-ok", response
            transport = worker.transport
            from enclave_gateway.security.attestation import verify
            challenge=__import__('secrets').token_hex(32)
            evidence=transport.attest(challenge)
            account=''
            if os.name=='nt':
                from enclave_gateway.security.isolation import process_identity
                account=process_identity().removeprefix('sid:')
            assert verify(evidence,challenge,expected_sha256=findings['worker_sha256'],require_signed=bool(trusted_signer),
                          trusted_signers=(trusted_signer,),expected_account=account)['verified']
            def guard():
                nonce=__import__('secrets').token_hex(32)
                data=transport.attest(nonce)
                runtime_hash=hashlib.sha256(Path(runtime).read_bytes()).hexdigest() if runtime else ''
                return verify(data,nonce,expected_sha256=findings['worker_sha256'],require_signed=bool(trusted_signer),
                              trusted_signers=(trusted_signer,),expected_account=account,
                              require_process_isolation=(os.name=='nt'),expected_runtime_sha256=runtime_hash)
            transport.attestation_guard=guard
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
            if os.name=='nt':
                with ThreadPoolExecutor(max_workers=4) as pool:
                    pending=[pool.submit(worker.raw,'native_fair_'+str(i),"Start-Sleep -Seconds 2; Write-Output 'native-ready'") for i in range(4)]
                    time.sleep(0.1)
                    started=time.monotonic()
                    echoed,eof=transport.mux_io(first,b'native-launch-fairness',read_wait_ms=100)
                    elapsed=time.monotonic()-started
                    assert echoed==b'native-launch-fairness' and not eof
                    assert elapsed<0.8,elapsed
                    findings['fast_io_during_native_launch_ms']=round(elapsed*1000)
                    for future in pending:
                        result=future.result(timeout=20)
                        assert result.exit_code==0 and result.stdout=='native-ready',result
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
                payload = (bytes(range(256)) * ((size+255)//256))[:size]
                source.write_bytes(payload)
                expected = hashlib.sha256(payload).hexdigest()
                assert transport.push_file(source, str(destination)) == expected
                assert transport.pull_file(str(destination), retrieved) == expected
                assert retrieved.read_bytes() == payload
            # Exercise the actual maximum without compression hiding its wire
            # size, including the final partial stripe and native stdin path.
            old_block,old_compress=transport.spec.block_size_bytes,transport.spec.compress
            try:
                transport.spec.block_size_bytes=4*1024*1024;transport.spec.compress=False
                payload=os.urandom(4*1024*1024+1)
                source.write_bytes(payload)
                expected=hashlib.sha256(payload).hexdigest()
                assert transport.push_file(source,str(destination))==expected
                assert transport.pull_file(str(destination),retrieved)==expected
                assert retrieved.read_bytes()==payload
                findings['maximum_uncompressed_block_bytes']=transport.spec.block_size_bytes
            finally:
                transport.spec.block_size_bytes,transport.spec.compress=old_block,old_compress
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
            if os.name=='nt':
                import ctypes
                from ctypes import wintypes
                kernel=ctypes.WinDLL('kernel32',use_last_error=True)
                kernel.CreateFileW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
                kernel.CreateFileW.restype=wintypes.HANDLE
                kernel.CloseHandle.argtypes=[wintypes.HANDLE]
                publisher=transport.control.publish_bytes
                releasers=[]
                def locked_publish(data,path):
                    if str(path).endswith('req_tx_shared_read.json'):
                        target=transport.control.path(path);temporary=target.with_suffix('.locked')
                        temporary.write_bytes(data)
                        handle=kernel.CreateFileW(str(temporary),0x40000000,4,None,3,0x80,None)
                        if handle==ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
                        try: temporary.replace(target)
                        except BaseException: kernel.CloseHandle(handle);raise
                        timer=threading.Timer(0.3,lambda:kernel.CloseHandle(handle));timer.start();releasers.append(timer)
                    else: publisher(data,path)
                transport.control.publish_bytes=locked_publish
                try:
                    retry_marker=root/'read-retry-once'
                    script="[IO.File]::AppendAllText("+ps_quote(str(retry_marker))+",'x'); Write-Output 'read-retry-ok'"
                    retried=worker.raw('tx_shared_read',script)
                    assert retried.exit_code==0 and retried.stdout=='read-retry-ok',retried
                    assert retry_marker.read_text()=='x'
                    findings['pre_dispatch_sharing_retry']='passed'
                finally:
                    transport.control.publish_bytes=publisher
                    for timer in releasers: timer.join(2)
            # Reject a mismatched envelope without overwriting another response.
            sentinel=worker.spool/'res_tx_identity_target.json'
            sentinel.write_bytes(b'unchanged-identity-fixture')
            forged={'tx_id':'tx_identity_target','op':'exec','timeout_ms':1000,'payload_b64':base64.b64encode(b"Write-Output 'forbidden'").decode()}
            worker.transport.control.publish_bytes(json.dumps(forged).encode(),str(worker.spool/'req_tx_identity_mismatch.json'))
            mismatched=worker.spool/'res_tx_identity_mismatch.json'
            deadline=time.monotonic()+10
            while True:
                from enclave_gateway.control.published import try_read_published
                raw=try_read_published(mismatched)
                if raw: break
                if time.monotonic()>deadline: raise AssertionError('Mismatched envelope did not receive a failure response')
                time.sleep(0.02)
            assert json.loads(raw)['exit_code']!=0
            assert sentinel.read_bytes()==b'unchanged-identity-fixture'
            sentinel.unlink();mismatched.unlink()
            findings['transaction_filename_binding']='passed'
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
            durations=[]
            exec_timeout=120 if os.name=='nt' else 30
            connections={}
            connection_lock=threading.Lock()
            def execute(index):
                if index % exec_every:
                    identity=threading.get_ident()
                    if identity not in connections:
                        connection=transport.mux_open('127.0.0.1',fast.port)
                        with connection_lock: connections[identity]=connection
                    payload=str(index).encode()
                    echoed,eof=transport.mux_io(connections[identity],payload,read_wait_ms=100)
                    assert echoed==payload and not eof,(echoed,eof)
                else:
                    result = transport.exec_bastion("Write-Output 'soak-ok'", timeout_sec=exec_timeout)
                    durations.append(result.duration_ms)
                    assert result.exit_code == 0 and result.stdout == "soak-ok", result
                if index % 100 == 0:
                    try: samples.append(json.loads(read_shared(worker.spool/'worker_state.json')))
                    except (ValueError, OSError): pass
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(execute, range(transactions)))
            for connection in connections.values(): transport.mux_close(connection)
            findings['exec_timeout_sec']=exec_timeout
            findings['maximum_exec_duration_ms']=max(durations)
            findings['exec_iterations']=(transactions+exec_every-1)//exec_every
            findings['mux_io_iterations']=transactions-findings['exec_iterations']
            findings["elapsed_sec"] = round(time.monotonic() - started, 3)
            time.sleep(2.1)
            final = json.loads(read_shared(worker.spool/'worker_state.json'))
            samples.append(final)
            findings["resource_samples"] = samples
            findings["handles_supported"] = os.name == "nt"
            findings["resource_acceptance"] = "sampled bounds, not proof of indefinite leak freedom"
            findings['signature_verification']='trusted-lab-signer' if trusted_signer else 'not_qualified'
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
            findings["checks"] = ["script-execution", "fresh-attestation", "mux-fairness", "binary-io", "half-close", "striped-files", "maximum-block-io", "restart-no-replay", "cancellation", "remote-timeout", "malformed-envelope", "refused-connect", "soak"]
            findings["status"] = "passed"
        finally:
            if evidence_directory:
                evidence_directory.mkdir(parents=True,exist_ok=True)
                packets=[]
                for source in worker.spool.glob('*'):
                    if not source.is_file() or not source.name.startswith(('req_','res_')): continue
                    item={'name':source.name}
                    try:
                        data=json.loads(read_shared(source))
                        item.update({key:data[key] for key in ('tx_id','op','mux_action','conn_id','expires_unix_ms','state','exit_code','duration_ms') if key in data})
                        if 'stdout_b64' in data: item['stdout_prefix']=base64.b64decode(data['stdout_b64'][:512]).decode('utf-8','replace')[:256]
                    except (OSError,ValueError): item['unreadable_or_partial']=True
                    packets.append(item)
                (evidence_directory/'packets.json').write_text(json.dumps(packets,indent=2),encoding='utf-8')
                import re
                failure=sys.exc_info()[1]
                tombstones={}
                for identifier in set(re.findall(r'tx_[0-9]+_[0-9a-f]+',str(failure))):
                    path=worker.spool/'.transactions'/(identifier+'.json')
                    try: tombstones[identifier]=json.loads(read_shared(path))
                    except (OSError,ValueError): tombstones[identifier]='missing'
                (evidence_directory/'failed-transactions.json').write_text(json.dumps(tombstones,indent=2),encoding='utf-8')
                if 'samples' in locals(): (evidence_directory/'samples.json').write_text(json.dumps(samples,indent=2),encoding='utf-8')
            worker.close(); fast.close(); slow.close()
            if evidence_directory:
                evidence_directory.mkdir(parents=True,exist_ok=True)
                for source,name in ((root/'worker.log','worker.log'),(worker.spool/'worker_state.json','worker_state.json')):
                    if source.exists(): shutil.copyfile(source,evidence_directory/name)
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--powershell", default=shutil.which("pwsh") or shutil.which("powershell"))
    parser.add_argument("--transactions", type=int, default=100)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--exec-every",type=int,default=1,help="Execute every Nth soak iteration; other iterations exercise persistent mux I/O")
    parser.add_argument("--runtime",type=Path)
    parser.add_argument("--allow-unsigned-lab",action="store_true")
    parser.add_argument('--trusted-signer',default='',help='Explicit lab signer trusted only inside the disposable guest')
    args = parser.parse_args()
    if not args.powershell: parser.error("A PowerShell executable is required")
    if not 1 <= args.transactions <= 100000: parser.error("transactions must be in 1..100000")
    if args.trusted_signer and (len(args.trusted_signer)!=40 or any(c not in '0123456789abcdefABCDEF' for c in args.trusted_signer)): parser.error('Invalid lab signer thumbprint')
    if args.trusted_signer and args.allow_unsigned_lab: parser.error('Select trusted signing or the unsigned fixture, not both')
    if os.name=='nt' and (not args.runtime or not (args.allow_unsigned_lab or args.trusted_signer)): parser.error('Disposable Windows fixture requires --runtime plus --trusted-signer or --allow-unsigned-lab')
    if not 1<=args.exec_every<=100: parser.error('--exec-every must be between 1 and 100')
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps({'status':'running','platform':sys.platform})+'\n',encoding='utf-8')
    failure=None
    try:
        result = run(args.powershell,args.transactions,args.runtime,args.allow_unsigned_lab,args.trusted_signer,args.exec_every,
                     args.output.with_suffix('.evidence') if args.output else None)
    except Exception as error:
        failure=error
        result={'status':'failed','platform':sys.platform,'error_type':type(error).__name__,'message':str(error)[:4096]}
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n",encoding="utf-8")
    print(text)
    if failure is not None: raise failure


if __name__ == "__main__":
    main()
