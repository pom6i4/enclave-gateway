"""RDP Virtual File System ([MS-RDPEFS] / rdpdr) IPC Transport, Delta Sync, and TCP Relay."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from enclave_gateway.config import BastionSpec
from enclave_gateway.control.qga_client import ControlChannel, ExecResult


@dataclass(slots=True)
class BlockDigest:
    index: int
    offset: int
    size: int
    sha256: str


def compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while chunk := fp.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower()


def compute_block_manifest(path: Path, block_size: int = 4 * 1024 * 1024) -> list[BlockDigest]:
    blocks: list[BlockDigest] = []
    offset = 0
    idx = 0
    with path.open("rb") as fp:
        while chunk := fp.read(block_size):
            digest = hashlib.sha256(chunk).hexdigest().lower()
            blocks.append(
                BlockDigest(index=idx, offset=offset, size=len(chunk), sha256=digest)
            )
            offset += len(chunk)
            idx += 1
    return blocks


def generate_tx_id() -> str:
    return f"tx_{int(time.time() * 1000)}_{secrets.token_hex(4)}"


class RdpVfsTransport:
    """Executes transactions and transfers files between Appliance and Bastion via [MS-RDPEFS]."""

    def __init__(self, control: ControlChannel, spec: BastionSpec) -> None:
        self.control = control
        self.spec = spec

    def exec_bastion(self, ps_script: str, timeout_sec: float = 120.0) -> ExecResult:
        """Dispatch a PowerShell script to BastionWorker via transactional JSON envelope."""
        tx_id = generate_tx_id()
        envelope = {
            "tx_id": tx_id,
            "op": "exec",
            "payload_b64": base64.b64encode(ps_script.encode("utf-8")).decode("ascii"),
            "timeout_ms": int(timeout_sec * 1000),
        }
        return self._dispatch_envelope(envelope, timeout_sec=timeout_sec)

    def _dispatch_envelope(
        self, envelope: dict[str, Any], timeout_sec: float = 120.0
    ) -> ExecResult:
        tx_id = str(envelope["tx_id"])
        envelope_b64 = base64.b64encode(
            json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        spool = self.spec.appliance_spool_dir
        iters = max(10, int(timeout_sec / 0.15))

        appliance_ps = f"""
$spool = '{spool}'
if (-not (Test-Path $spool)) {{ New-Item -ItemType Directory -Force -Path $spool | Out-Null }}
$reqTmp = Join-Path $spool 'req_{tx_id}.tmp'
$reqFile = Join-Path $spool 'req_{tx_id}.json'
$resFile = Join-Path $spool 'res_{tx_id}.json'
Remove-Item $reqTmp, $reqFile, $resFile -Force -ErrorAction SilentlyContinue
[IO.File]::WriteAllBytes($reqTmp, [Convert]::FromBase64String('{envelope_b64}'))
Move-Item $reqTmp $reqFile -Force

for ($i = 0; $i -lt {iters}; $i++) {{
    if (Test-Path $resFile) {{
        Start-Sleep -Milliseconds 40
        $raw = Get-Content $resFile -Raw -Encoding UTF8
        Remove-Item $resFile, $reqFile -Force -ErrorAction SilentlyContinue
        [Console]::OutputEncoding = [Text.Encoding]::UTF8
        Write-Output $raw
        exit 0
    }}
    Start-Sleep -Milliseconds 150
}}
Remove-Item $reqFile -Force -ErrorAction SilentlyContinue
Write-Error 'Timed out waiting for BastionWorker response for {tx_id}'
exit 124
"""
        started = time.monotonic()
        res = self.control.exec_powershell(appliance_ps, timeout_sec=timeout_sec + 15.0)
        if res.exit_code != 0:
            return ExecResult(
                exit_code=res.exit_code,
                stdout="",
                stderr=res.stderr or f"Bastion IPC failed (code {res.exit_code})",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        try:
            parsed = json.loads(res.stdout)
            stdout_str = (
                base64.b64decode(parsed.get("stdout_b64", ""))
                .decode("utf-8", errors="replace")
                .replace("\r\n", "\n")
                .strip()
            )
            stderr_str = (
                base64.b64decode(parsed.get("stderr_b64", ""))
                .decode("utf-8", errors="replace")
                .replace("\r\n", "\n")
                .strip()
            )
            return ExecResult(
                exit_code=int(parsed.get("exit_code", 0)),
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=int(parsed.get("duration_ms", res.duration_ms)),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            return ExecResult(
                exit_code=1,
                stdout=res.stdout,
                stderr=f"Malformed BastionWorker response: {exc}",
                duration_ms=res.duration_ms,
            )

    def push_file(
        self,
        local_path: Path,
        bastion_dest_path: str,
        *,
        use_delta: bool = True,
        timeout_sec: float = 900.0,
    ) -> str:
        """Push a file from Host to Bastion with SHA-256 verification and optional block delta sync."""
        file_sha = compute_file_sha256(local_path)
        file_size = local_path.stat().st_size
        block_size = self.spec.block_size_bytes

        # Step 1: Fast pre-check if identical file already exists on Bastion
        check_ps = f"""
$dst = '{bastion_dest_path}'
if (Test-Path $dst) {{
    $item = Get-Item $dst
    if ($item.Length -eq {file_size}) {{
        $h = (Get-FileHash -Algorithm SHA256 $dst).Hash.ToLower()
        if ($h -eq '{file_sha}') {{ Write-Output 'MATCH'; exit 0 }}
        if ('{str(use_delta).lower()}' -eq 'true') {{
            $fs = [IO.File]::OpenRead($dst)
            $sha = [Security.Cryptography.SHA256]::Create()
            $buf = New-Object byte[] {block_size}
            $hashes = @()
            try {{
                while (($read = $fs.Read($buf, 0, $buf.Length)) -gt 0) {{
                    $hashBytes = $sha.ComputeHash($buf, 0, $read)
                    $hashes += ([BitConverter]::ToString($hashBytes).Replace('-', '').ToLower())
                }}
            }} finally {{
                $fs.Close()
                $sha.Dispose()
            }}
            Write-Output ('BLOCKS:' + ($hashes -join ','))
            exit 0
        }}
    }}
}}
Write-Output 'MISS'
"""
        probe = self.exec_bastion(check_ps, timeout_sec=60.0)
        if probe.exit_code == 0 and probe.stdout.strip() == "MATCH":
            return file_sha

        remote_block_hashes: list[str] = []
        if probe.exit_code == 0 and probe.stdout.startswith("BLOCKS:"):
            raw_hashes = probe.stdout.partition("BLOCKS:")[2].strip()
            if raw_hashes:
                remote_block_hashes = raw_hashes.split(",")

        tx_id = generate_tx_id()
        manifest = compute_block_manifest(local_path, block_size=block_size)

        changed_indices: list[int] = []
        with local_path.open("rb") as fp:
            for blk in manifest:
                if (
                    use_delta
                    and blk.index < len(remote_block_hashes)
                    and remote_block_hashes[blk.index] == blk.sha256
                ):
                    continue
                fp.seek(blk.offset)
                raw_chunk = fp.read(blk.size)
                payload = (
                    zlib.compress(raw_chunk, level=6)
                    if self.spec.compress
                    else raw_chunk
                )
                guest_chunk_path = (
                    f"{self.spec.appliance_spool_dir}\\chunk_{tx_id}_{blk.index:05d}.bin"
                )
                self.control.write_bytes(payload, guest_chunk_path)
                changed_indices.append(blk.index)

        idx_csv = ",".join(str(i) for i in changed_indices)
        compressed_flag = "$true" if self.spec.compress else "$false"

        assemble_ps = f"""
$vfsSpool = '{self.spec.bastion_spool_dir}'
$dst = '{bastion_dest_path}'
$tmp = "$dst.tmp_{tx_id}"
$parent = Split-Path -Parent $dst
if ($parent -and -not (Test-Path $parent)) {{ New-Item -ItemType Directory -Force -Path $parent | Out-Null }}

if ((Test-Path $dst) -and '{str(use_delta).lower()}' -eq 'true') {{
    Copy-Item $dst $tmp -Force
}} else {{
    $emptyFs = [IO.File]::Create($tmp)
    $emptyFs.SetLength({file_size})
    $emptyFs.Close()
}}

$changed = @({idx_csv})
$outFs = [IO.File]::Open($tmp, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {{
    foreach ($idx in $changed) {{
        $chunkName = ('chunk_{tx_id}_{{0:D5}}.bin' -f [int]$idx)
        $chunkPath = Join-Path $vfsSpool $chunkName
        $rawBytes = [IO.File]::ReadAllBytes($chunkPath)
        if ({compressed_flag}) {{
            $ms = New-Object IO.MemoryStream(,$rawBytes)
            # Skip 2-byte zlib header (0x78 0x9C) for DeflateStream compatibility
            $ms.Position = 2
            $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
            $outMs = New-Object IO.MemoryStream
            $ds.CopyTo($outMs)
            $ds.Close()
            $dataBytes = $outMs.ToArray()
        }} else {{
            $dataBytes = $rawBytes
        }}
        $offset = [int64]$idx * [int64]{block_size}
        $outFs.Seek($offset, [IO.SeekOrigin]::Begin) | Out-Null
        $outFs.Write($dataBytes, 0, $dataBytes.Length)
        Remove-Item $chunkPath -Force -ErrorAction SilentlyContinue
    }}
    $outFs.SetLength({file_size})
}} finally {{
    $outFs.Close()
}}

$actualSha = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
if ($actualSha -ne '{file_sha}') {{
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Error "SHA-256 verification failed on Bastion: expected {file_sha}, got $actualSha"
    exit 1
}}
Move-Item $tmp $dst -Force
Write-Output "VERIFIED:$actualSha"
"""
        res = self.exec_bastion(assemble_ps, timeout_sec=timeout_sec)
        if res.exit_code != 0 or f"VERIFIED:{file_sha}" not in res.stdout:
            raise RuntimeError(
                f"Bastion file transfer failed for {bastion_dest_path}: {res.stderr or res.stdout}"
            )
        return file_sha

    def pull_file(
        self, bastion_src_path: str, local_dest_path: Path, timeout_sec: float = 600.0
    ) -> str:
        """Pull a file from Bastion to Host with SHA-256 integrity verification."""
        tx_id = generate_tx_id()
        stage_name = f"pull_{tx_id}.bin"
        bastion_stage = f"{self.spec.bastion_spool_dir}\\{stage_name}"
        appliance_stage = f"{self.spec.appliance_spool_dir}\\{stage_name}"

        stage_ps = f"""
$src = '{bastion_src_path}'
if (-not (Test-Path $src)) {{ Write-Error "Source file not found: $src"; exit 1 }}
$sha = (Get-FileHash -Algorithm SHA256 $src).Hash.ToLower()
Copy-Item $src '{bastion_stage}' -Force
Write-Output "SHA256:$sha"
"""
        res = self.exec_bastion(stage_ps, timeout_sec=timeout_sec)
        if res.exit_code != 0 or "SHA256:" not in res.stdout:
            raise RuntimeError(
                f"Failed to stage file from Bastion ({bastion_src_path}): {res.stderr or res.stdout}"
            )
        expected_sha = res.stdout.partition("SHA256:")[2].strip().splitlines()[0].strip()

        try:
            self.control.read_file(appliance_stage, local_dest_path)
        finally:
            self.control.exec_powershell(
                f"Remove-Item '{appliance_stage}' -Force -ErrorAction SilentlyContinue"
            )

        actual_sha = compute_file_sha256(local_dest_path)
        if actual_sha != expected_sha:
            local_dest_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"SHA-256 mismatch on pulled file {local_dest_path}: expected {expected_sha}, got {actual_sha}"
            )
        return actual_sha

    def relay_tcp_exchange(
        self, target_host: str, target_port: int, payload: bytes, timeout_sec: float = 30.0
    ) -> bytes:
        """Relay a TCP request-response exchange through BastionWorker over [MS-RDPEFS]."""
        b64_in = base64.b64encode(payload).decode("ascii")
        relay_ps = f"""
$client = New-Object System.Net.Sockets.TcpClient
$client.ReceiveTimeout = {int(timeout_sec * 1000)}
$client.SendTimeout = {int(timeout_sec * 1000)}
try {{
    $client.Connect('{target_host}', {target_port})
    $stream = $client.GetStream()
    $inBytes = [Convert]::FromBase64String('{b64_in}')
    if ($inBytes.Length -gt 0) {{
        $stream.Write($inBytes, 0, $inBytes.Length)
        $stream.Flush()
    }}
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 65536
    $stream.ReadTimeout = 2000
    try {{
        while (($r = $stream.Read($buf, 0, $buf.Length)) -gt 0) {{
            $ms.Write($buf, 0, $r)
            if (-not $stream.DataAvailable) {{ break }}
        }}
    }} catch [System.IO.IOException] {{}}
    Write-Output ([Convert]::ToBase64String($ms.ToArray()))
}} finally {{
    $client.Close()
}}
"""
        res = self.exec_bastion(relay_ps, timeout_sec=timeout_sec + 5.0)
        if res.exit_code != 0:
            raise ConnectionError(
                f"TCP-over-VFS relay to {target_host}:{target_port} failed: {res.stderr}"
            )
        out_b64 = res.stdout.strip()
        return base64.b64decode(out_b64) if out_b64 else b""


class RdpVfsTunnelServer:
    """Local TCP listener on 127.0.0.1 that tunnels connections over RdpVfsTransport."""

    def __init__(
        self,
        transport: RdpVfsTransport,
        local_port: int,
        target_host: str,
        target_port: int,
    ) -> None:
        self.transport = transport
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.local_port))
        srv.listen(16)
        srv.settimeout(1.0)
        self._server_socket = srv
        try:
            while not self._stop_event.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self._handle_client, args=(conn,), daemon=True
                ).start()
        finally:
            srv.close()

    def stop(self) -> None:
        self._stop_event.set()

    def _handle_client(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        try:
            chunks: list[bytes] = []
            try:
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    if len(data) < 65536:
                        break
            except socket.timeout:
                pass
            req_bytes = b"".join(chunks)
            resp_bytes = self.transport.relay_tcp_exchange(
                self.target_host, self.target_port, req_bytes
            )
            if resp_bytes:
                conn.sendall(resp_bytes)
        except Exception:
            pass
        finally:
            conn.close()
