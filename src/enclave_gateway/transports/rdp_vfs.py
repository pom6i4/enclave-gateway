"""RDP Virtual File System ([MS-RDPEFS] / rdpdr) IPC Transport, Parallel Striped I/O, and TCP Relay."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
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


def build_parallel_striped_assemble_ps(
    *,
    vfs_spool: str,
    bastion_dest_path: str,
    tx_id: str,
    file_size: int,
    block_size: int,
    changed_indices: list[int],
    compress: bool,
    use_delta: bool,
    parallel_streams: int,
    expected_sha256: str,
) -> str:
    """Build PowerShell script that uses a RunspacePool for parallel striped chunk reading & assembly."""
    idx_csv = ",".join(str(i) for i in changed_indices)
    compressed_flag = "$true" if compress else "$false"
    streams = max(1, int(parallel_streams))

    return f"""
$vfsSpool = '{vfs_spool}'
$dst = [Environment]::ExpandEnvironmentVariables('{bastion_dest_path}')
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
$maxStreams = [Math]::Max(1, {streams})
$ownPool = $false
if ($Global:EnclaveRunspacePool -and $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -eq 'Opened') {{
    $pool = $Global:EnclaveRunspacePool
}} else {{
    $pool = [runspacefactory]::CreateRunspacePool(1, $maxStreams)
    $pool.Open()
    $ownPool = $true
}}

$stripeWorker = {{
    param([int]$Idx, [string]$Spool, [string]$TxId, [string]$TmpPath, [int64]$BlockSize, [bool]$IsCompressed)
    $chunkName = ('chunk_{{0}}_{{1:D5}}.bin' -f $TxId, $Idx)
    $chunkPath = Join-Path $Spool $chunkName
    $rawBytes = [IO.File]::ReadAllBytes($chunkPath)
    if ($IsCompressed) {{
        $ms = New-Object IO.MemoryStream(,$rawBytes)
        $ms.Position = 2
        $ds = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)
        $outMs = New-Object IO.MemoryStream
        $ds.CopyTo($outMs)
        $ds.Close()
        $dataBytes = $outMs.ToArray()
    }} else {{
        $dataBytes = $rawBytes
    }}
    $fs = [IO.File]::Open($TmpPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {{
        $offset = [int64]$Idx * $BlockSize
        $fs.Seek($offset, [IO.SeekOrigin]::Begin) | Out-Null
        $fs.Write($dataBytes, 0, $dataBytes.Length)
    }} finally {{
        $fs.Close()
    }}
    Remove-Item $chunkPath -Force -ErrorAction SilentlyContinue
}}

$jobs = New-Object System.Collections.Generic.List[object]
try {{
    foreach ($idx in $changed) {{
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($stripeWorker).AddArgument([int]$idx).AddArgument($vfsSpool).AddArgument('{tx_id}').AddArgument($tmp).AddArgument([int64]{block_size}).AddArgument({compressed_flag})
        $jobs.Add(@{{ Pipe = $ps; Handle = $ps.BeginInvoke() }})
    }}
    foreach ($job in $jobs) {{
        [void]$job.Pipe.EndInvoke($job.Handle)
        if ($job.Pipe.Streams.Error.Count -gt 0) {{
            throw $job.Pipe.Streams.Error[0].Exception
        }}
        $job.Pipe.Dispose()
    }}
}} finally {{
    if ($ownPool) {{
        $pool.Close()
        $pool.Dispose()
    }}
}}

$truncFs = [IO.File]::Open($tmp, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {{
    $truncFs.SetLength({file_size})
}} finally {{
    $truncFs.Close()
}}

$actualSha = (Get-FileHash -Algorithm SHA256 $tmp).Hash.ToLower()
if ($actualSha -ne '{expected_sha256}') {{
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Error "SHA-256 verification failed on Bastion: expected {expected_sha256}, got $actualSha"
    exit 1
}}
Move-Item $tmp $dst -Force
Write-Output "VERIFIED:$actualSha"
"""


def build_parallel_striped_stage_ps(
    *,
    bastion_src_path: str,
    vfs_spool: str,
    tx_id: str,
    block_size: int,
    parallel_streams: int,
) -> str:
    """Build PowerShell script that stages a file from Bastion to VFS spool using parallel striped RunspacePool I/O."""
    streams = max(1, int(parallel_streams))
    return f"""
$src = [Environment]::ExpandEnvironmentVariables('{bastion_src_path}')
if (-not (Test-Path $src)) {{ Write-Error "Source file not found: $src"; exit 1 }}
$item = Get-Item $src
$fileSize = [int64]$item.Length
$sha = (Get-FileHash -Algorithm SHA256 $src).Hash.ToLower()
$blockSize = [int64]{block_size}

if ($fileSize -le $blockSize -or {streams} -le 1) {{
    $stagePath = Join-Path '{vfs_spool}' 'pull_{tx_id}.bin'
    Copy-Item $src $stagePath -Force
    Write-Output "SHA256:$sha:CHUNKS:0"
    exit 0
}}

$numChunks = [int][Math]::Ceiling([double]$fileSize / [double]$blockSize)
$maxStreams = [Math]::Max(1, {streams})
$ownPool = $false
if ($Global:EnclaveRunspacePool -and $Global:EnclaveRunspacePool.RunspacePoolStateInfo.State -eq 'Opened') {{
    $pool = $Global:EnclaveRunspacePool
}} else {{
    $pool = [runspacefactory]::CreateRunspacePool(1, $maxStreams)
    $pool.Open()
    $ownPool = $true
}}

$stageWorker = {{
    param([int]$Idx, [string]$SrcPath, [string]$Spool, [string]$TxId, [int64]$BlockSize, [int64]$TotalSize)
    $offset = [int64]$Idx * $BlockSize
    $toRead = [int][Math]::Min($BlockSize, $TotalSize - $offset)
    $buf = New-Object byte[] $toRead
    $fs = [IO.File]::Open($SrcPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {{
        $fs.Seek($offset, [IO.SeekOrigin]::Begin) | Out-Null
        $readTotal = 0
        while ($readTotal -lt $toRead) {{
            $r = $fs.Read($buf, $readTotal, $toRead - $readTotal)
            if ($r -le 0) {{ break }}
            $readTotal += $r
        }}
    }} finally {{
        $fs.Close()
    }}
    $chunkName = ('pull_{{0}}_{{1:D5}}.bin' -f $TxId, $Idx)
    $chunkPath = Join-Path $Spool $chunkName
    [IO.File]::WriteAllBytes($chunkPath, $buf)
}}

$jobs = New-Object System.Collections.Generic.List[object]
try {{
    for ($i = 0; $i -lt $numChunks; $i++) {{
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($stageWorker).AddArgument([int]$i).AddArgument($src).AddArgument('{vfs_spool}').AddArgument('{tx_id}').AddArgument($blockSize).AddArgument($fileSize)
        $jobs.Add(@{{ Pipe = $ps; Handle = $ps.BeginInvoke() }})
    }}
    foreach ($job in $jobs) {{
        [void]$job.Pipe.EndInvoke($job.Handle)
        if ($job.Pipe.Streams.Error.Count -gt 0) {{
            throw $job.Pipe.Streams.Error[0].Exception
        }}
        $job.Pipe.Dispose()
    }}
}} finally {{
    if ($ownPool) {{
        $pool.Close()
        $pool.Dispose()
    }}
}}

Write-Output "SHA256:$sha:CHUNKS:$numChunks"
"""


class RdpVfsTransport:
    """Executes transactions and transfers files between Appliance and Bastion via [MS-RDPEFS]."""

    def __init__(self, control: ControlChannel, spec: BastionSpec) -> None:
        self.control = control
        self.spec = spec

    def exec_bastion(
        self,
        ps_script: str,
        timeout_sec: float = 120.0,
        *,
        op: str = "exec",
        extra_fields: dict[str, Any] | None = None,
    ) -> ExecResult:
        """Dispatch a PowerShell script to BastionWorker via transactional JSON envelope."""
        tx_id = generate_tx_id()
        envelope: dict[str, Any] = {
            "tx_id": tx_id,
            "op": op,
            "payload_b64": base64.b64encode(ps_script.encode("utf-8")).decode("ascii"),
            "timeout_ms": int(timeout_sec * 1000),
        }
        if extra_fields:
            envelope.update(extra_fields)
        return self._dispatch_envelope(envelope, timeout_sec=timeout_sec)

    def _dispatch_envelope(
        self, envelope: dict[str, Any], timeout_sec: float = 120.0
    ) -> ExecResult:
        tx_id = str(envelope["tx_id"])
        raw_envelope = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        spool = self.spec.appliance_spool_dir.rstrip("\\/")
        started = time.monotonic()

        try_read_fn = getattr(self.control, "try_read_bytes", None)
        if getattr(self.control, "supports_direct_spool_ipc", False) and callable(
            try_read_fn
        ):
            req_guest = f"{spool}\\req_{tx_id}.json"
            res_guest = f"{spool}\\res_{tx_id}.json"
            self.control.write_bytes(raw_envelope, req_guest)
            deadline = time.monotonic() + timeout_sec
            delay = 0.005
            raw_res_text = ""
            while time.monotonic() < deadline:
                res_bytes = try_read_fn(res_guest, truncate_after_read=True)
                if res_bytes:
                    raw_res_text = res_bytes.decode("utf-8", errors="replace").strip()
                    if raw_res_text:
                        break
                time.sleep(delay)
                delay = min(0.035, delay * 1.4)

            if not raw_res_text:
                return ExecResult(
                    exit_code=124,
                    stdout="",
                    stderr=f"Timed out waiting for BastionWorker response for {tx_id}",
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            return self._parse_envelope_response(
                raw_res_text, int((time.monotonic() - started) * 1000)
            )

        envelope_b64 = base64.b64encode(raw_envelope).decode("ascii")
        iters = max(10, int(timeout_sec / 0.15))

        appliance_ps = f"""
$spool = '{spool}'
if (-not (Test-Path $spool)) {{ New-Item -ItemType Directory -Force -Path $spool | Out-Null }}
$reqTmp = Join-Path $spool 'req_{tx_id}.tmp'
$reqFile = Join-Path $spool 'req_{tx_id}.json'
$resFile = Join-Path $spool 'res_{tx_id}.json'
Remove-Item $reqTmp, $reqFile, $resFile -Force -ErrorAction SilentlyContinue
$fsw = New-Object System.IO.FileSystemWatcher($spool, 'res_{tx_id}.json')
try {{
    [IO.File]::WriteAllBytes($reqTmp, [Convert]::FromBase64String('{envelope_b64}'))
    Move-Item $reqTmp $reqFile -Force
    for ($i = 0; $i -lt {iters}; $i++) {{
        if (-not (Test-Path $resFile)) {{
            [void]$fsw.WaitForChanged([System.IO.WatcherChangeTypes]::Created -bor [System.IO.WatcherChangeTypes]::Renamed, 150)
        }}
        if (Test-Path $resFile) {{
            Start-Sleep -Milliseconds 15
            $raw = Get-Content $resFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            if ($raw) {{
                Remove-Item $resFile, $reqFile -Force -ErrorAction SilentlyContinue
                [Console]::OutputEncoding = [Text.Encoding]::UTF8
                Write-Output $raw
                exit 0
            }}
        }}
    }}
}} finally {{
    $fsw.Dispose()
}}
Remove-Item $reqFile -Force -ErrorAction SilentlyContinue
Write-Error 'Timed out waiting for BastionWorker response for {tx_id}'
exit 124
"""
        res = self.control.exec_powershell(appliance_ps, timeout_sec=timeout_sec + 15.0)
        if res.exit_code != 0:
            return ExecResult(
                exit_code=res.exit_code,
                stdout="",
                stderr=res.stderr or f"Bastion IPC failed (code {res.exit_code})",
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return self._parse_envelope_response(res.stdout, res.duration_ms)

    @staticmethod
    def _parse_envelope_response(raw_stdout: str, fallback_duration_ms: int) -> ExecResult:
        try:
            parsed = json.loads(raw_stdout)
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
                duration_ms=int(parsed.get("duration_ms", fallback_duration_ms)),
            )
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            return ExecResult(
                exit_code=1,
                stdout=raw_stdout,
                stderr=f"Malformed BastionWorker response: {exc}",
                duration_ms=fallback_duration_ms,
            )

    def push_file(
        self,
        local_path: Path,
        bastion_dest_path: str,
        *,
        use_delta: bool = True,
        timeout_sec: float = 900.0,
    ) -> str:
        """Push a file from Host to Bastion with SHA-256 verification, block delta sync, and Parallel Striped I/O."""
        file_sha = compute_file_sha256(local_path)
        file_size = local_path.stat().st_size
        block_size = self.spec.block_size_bytes

        # Step 1: Fast pre-check if identical file already exists on Bastion
        check_ps = f"""
$dst = [Environment]::ExpandEnvironmentVariables('{bastion_dest_path}')
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

        blocks_to_stage: list[BlockDigest] = []
        for blk in manifest:
            if (
                use_delta
                and blk.index < len(remote_block_hashes)
                and remote_block_hashes[blk.index] == blk.sha256
            ):
                continue
            blocks_to_stage.append(blk)

        def _stage_single_block(blk: BlockDigest) -> int:
            with local_path.open("rb") as fp:
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
            return blk.index

        max_workers = max(1, min(self.spec.parallel_streams, len(blocks_to_stage) or 1))
        if max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                changed_indices = list(pool.map(_stage_single_block, blocks_to_stage))
        else:
            changed_indices = [_stage_single_block(b) for b in blocks_to_stage]

        assemble_ps = build_parallel_striped_assemble_ps(
            vfs_spool=self.spec.bastion_spool_dir,
            bastion_dest_path=bastion_dest_path,
            tx_id=tx_id,
            file_size=file_size,
            block_size=block_size,
            changed_indices=changed_indices,
            compress=self.spec.compress,
            use_delta=use_delta,
            parallel_streams=self.spec.parallel_streams,
            expected_sha256=file_sha,
        )
        res = self.exec_bastion(assemble_ps, timeout_sec=timeout_sec)
        if res.exit_code != 0 or f"VERIFIED:{file_sha}" not in res.stdout:
            raise RuntimeError(
                f"Bastion file transfer failed for {bastion_dest_path}: {res.stderr or res.stdout}"
            )
        return file_sha

    def pull_file(
        self, bastion_src_path: str, local_dest_path: Path, timeout_sec: float = 600.0
    ) -> str:
        """Pull a file from Bastion to Host with Parallel Striped I/O and SHA-256 verification."""
        tx_id = generate_tx_id()
        stage_ps = build_parallel_striped_stage_ps(
            bastion_src_path=bastion_src_path,
            vfs_spool=self.spec.bastion_spool_dir,
            tx_id=tx_id,
            block_size=self.spec.block_size_bytes,
            parallel_streams=self.spec.parallel_streams,
        )
        res = self.exec_bastion(stage_ps, timeout_sec=timeout_sec)
        if res.exit_code != 0 or "SHA256:" not in res.stdout:
            raise RuntimeError(
                f"Failed to stage file from Bastion ({bastion_src_path}): {res.stderr or res.stdout}"
            )

        marker_line = [
            ln.strip() for ln in res.stdout.splitlines() if ln.strip().startswith("SHA256:")
        ][0]
        parts = marker_line.split(":")
        expected_sha = parts[1].strip().lower()
        num_chunks = int(parts[3]) if len(parts) >= 4 and parts[2] == "CHUNKS" else 0

        local_dest_path.parent.mkdir(parents=True, exist_ok=True)
        if num_chunks <= 0:
            appliance_stage = f"{self.spec.appliance_spool_dir}\\pull_{tx_id}.bin"
            try:
                self.control.read_file(appliance_stage, local_dest_path)
            finally:
                self.control.exec_powershell(
                    f"Remove-Item '{appliance_stage}' -Force -ErrorAction SilentlyContinue"
                )
        else:
            def _fetch_chunk(idx: int) -> tuple[int, bytes]:
                chunk_guest = (
                    f"{self.spec.appliance_spool_dir}\\pull_{tx_id}_{idx:05d}.bin"
                )
                try:
                    data = self.control.read_bytes(chunk_guest)
                    return idx, data
                finally:
                    self.control.exec_powershell(
                        f"Remove-Item '{chunk_guest}' -Force -ErrorAction SilentlyContinue"
                    )

            max_workers = max(1, min(self.spec.parallel_streams, num_chunks))
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                chunks = list(pool.map(_fetch_chunk, range(num_chunks)))
            chunks.sort(key=lambda item: item[0])
            with local_dest_path.open("wb") as fp:
                for _, chunk_bytes in chunks:
                    fp.write(chunk_bytes)

        actual_sha = compute_file_sha256(local_dest_path)
        if actual_sha != expected_sha:
            local_dest_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"SHA-256 mismatch on pulled file {local_dest_path}: expected {expected_sha}, got {actual_sha}"
            )
        return actual_sha

    def mux_open(
        self, target_host: str, target_port: int, timeout_sec: float = 15.0
    ) -> str:
        """Open a persistent multiplexed TCP connection inside BastionWorker."""
        conn_id = f"mux_{secrets.token_hex(6)}"
        open_ps = f"""
if (-not $Global:EnclaveMuxSockets) {{
    $Global:EnclaveMuxSockets = [hashtable]::Synchronized(@{{}})
}}
$client = New-Object System.Net.Sockets.TcpClient
$client.NoDelay = $true
$client.ReceiveTimeout = {int(timeout_sec * 1000)}
$client.SendTimeout = {int(timeout_sec * 1000)}
$client.Connect('{target_host}', {target_port})
$stream = $client.GetStream()
$Global:EnclaveMuxSockets['{conn_id}'] = @{{
    Client     = $client
    Stream     = $stream
    Target     = '{target_host}:{target_port}'
    LastActive = (Get-Date)
}}
Write-Output 'MUX_OPEN_OK:{conn_id}'
"""
        res = self.exec_bastion(
            open_ps,
            timeout_sec=timeout_sec + 5.0,
            op="mux",
            extra_fields={
                "mux_action": "open",
                "conn_id": conn_id,
                "target_host": target_host,
                "target_port": int(target_port),
            },
        )
        if res.exit_code != 0 or f"MUX_OPEN_OK:{conn_id}" not in res.stdout:
            raise ConnectionError(
                f"Failed to open multiplexed TCP stream to {target_host}:{target_port}: {res.stderr or res.stdout}"
            )
        return conn_id

    def mux_io(
        self,
        conn_id: str,
        tx_data: bytes = b"",
        *,
        max_read_bytes: int = 65536,
        read_wait_ms: int = 100,
        timeout_sec: float = 15.0,
    ) -> tuple[bytes, bool]:
        """Perform bidirectional write + read on an active multiplexed TCP connection on Bastion."""
        b64_tx = base64.b64encode(tx_data).decode("ascii") if tx_data else ""
        io_ps = f"""
if (-not $Global:EnclaveMuxSockets -or -not $Global:EnclaveMuxSockets.ContainsKey('{conn_id}')) {{
    Write-Output 'MUX_EOF:'
    exit 0
}}
$entry = $Global:EnclaveMuxSockets['{conn_id}']
$client = $entry.Client
$stream = $entry.Stream
$entry.LastActive = (Get-Date)

if ('{b64_tx}' -ne '') {{
    $txBytes = [Convert]::FromBase64String('{b64_tx}')
    $stream.Write($txBytes, 0, $txBytes.Length)
    $stream.Flush()
}}

$ms = New-Object System.IO.MemoryStream
$buf = New-Object byte[] {max_read_bytes}
$eof = $false

$waited = 0
while (-not $stream.DataAvailable -and $waited -lt {read_wait_ms}) {{
    if ($client.Client.Poll(1000, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0) {{
        $eof = $true
        break
    }}
    Start-Sleep -Milliseconds 20
    $waited += 20
}}

while ($stream.DataAvailable -and $ms.Length -lt {max_read_bytes}) {{
    $toRead = [Math]::Min($buf.Length, {max_read_bytes} - [int]$ms.Length)
    $r = $stream.Read($buf, 0, $toRead)
    if ($r -le 0) {{
        $eof = $true
        break
    }}
    $ms.Write($buf, 0, $r)
}}

if (-not $eof -and $client.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0) {{
    $eof = $true
}}

$rxB64 = [Convert]::ToBase64String($ms.ToArray())
if ($eof) {{
    try {{ $client.Close() }} catch {{}}
    $Global:EnclaveMuxSockets.Remove('{conn_id}')
    Write-Output "MUX_EOF:$rxB64"
}} else {{
    Write-Output "MUX_DATA:$rxB64"
}}
"""
        res = self.exec_bastion(
            io_ps,
            timeout_sec=timeout_sec,
            op="mux",
            extra_fields={
                "mux_action": "io",
                "conn_id": conn_id,
                "tx_b64": b64_tx,
                "max_read_bytes": int(max_read_bytes),
                "read_wait_ms": int(read_wait_ms),
            },
        )
        if res.exit_code != 0:
            raise ConnectionError(
                f"Multiplexed I/O error on {conn_id}: {res.stderr or res.stdout}"
            )
        line = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "MUX_EOF:"
        if line.startswith("MUX_EOF:"):
            b64_part = line.partition("MUX_EOF:")[2].strip()
            return (base64.b64decode(b64_part) if b64_part else b""), True
        if line.startswith("MUX_DATA:"):
            b64_part = line.partition("MUX_DATA:")[2].strip()
            return (base64.b64decode(b64_part) if b64_part else b""), False
        return b"", True

    def mux_close(self, conn_id: str, timeout_sec: float = 10.0) -> None:
        """Close and remove a multiplexed TCP connection on Bastion."""
        close_ps = f"""
if ($Global:EnclaveMuxSockets -and $Global:EnclaveMuxSockets.ContainsKey('{conn_id}')) {{
    try {{ $Global:EnclaveMuxSockets['{conn_id}'].Client.Close() }} catch {{}}
    $Global:EnclaveMuxSockets.Remove('{conn_id}')
}}
Write-Output 'MUX_CLOSED'
"""
        self.exec_bastion(
            close_ps,
            timeout_sec=timeout_sec,
            op="mux",
            extra_fields={"mux_action": "close", "conn_id": conn_id},
        )

    def relay_tcp_exchange(
        self, target_host: str, target_port: int, payload: bytes, timeout_sec: float = 30.0
    ) -> bytes:
        """Relay a single TCP request-response exchange through BastionWorker over [MS-RDPEFS]."""
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


def pump_multiplexed_socket(
    transport: RdpVfsTransport,
    client_sock: socket.socket,
    target_host: str,
    target_port: int,
    *,
    stop_event: threading.Event | None = None,
    initial_tx: bytes = b"",
) -> None:
    """Pump a full-duplex TCP connection over RdpVfsTransport stateful multiplexing."""
    conn_id = transport.mux_open(target_host, target_port)
    client_sock.settimeout(0.03)
    pending_tx = initial_tx
    try:
        while stop_event is None or not stop_event.is_set():
            tx_chunks: list[bytes] = []
            if pending_tx:
                tx_chunks.append(pending_tx)
                pending_tx = b""
            client_eof = False
            try:
                data = client_sock.recv(65536)
                if data == b"":
                    client_eof = True
                elif data:
                    tx_chunks.append(data)
            except (socket.timeout, BlockingIOError):
                pass
            except OSError:
                client_eof = True

            tx_payload = b"".join(tx_chunks)
            rx_bytes, remote_eof = transport.mux_io(
                conn_id,
                tx_payload,
                read_wait_ms=40 if tx_payload else 100,
            )
            if rx_bytes:
                client_sock.settimeout(5.0)
                client_sock.sendall(rx_bytes)
                client_sock.settimeout(0.03)

            if remote_eof or client_eof:
                break
    finally:
        try:
            transport.mux_close(conn_id)
        except Exception:
            pass


class RdpVfsTunnelServer:
    """Local TCP listener on 127.0.0.1 that tunnels connections over RdpVfsTransport."""

    def __init__(
        self,
        transport: RdpVfsTransport,
        local_port: int,
        target_host: str,
        target_port: int,
        *,
        multiplexed: bool = True,
    ) -> None:
        self.transport = transport
        self.local_port = local_port
        self.target_host = target_host
        self.target_port = target_port
        self.multiplexed = multiplexed
        self._stop_event = threading.Event()
        self._server_socket: socket.socket | None = None

    def serve_forever(self) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.local_port))
        self.local_port = srv.getsockname()[1]
        srv.listen(16)
        srv.settimeout(0.5)
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
        try:
            if self.multiplexed:
                pump_multiplexed_socket(
                    self.transport,
                    conn,
                    self.target_host,
                    self.target_port,
                    stop_event=self._stop_event,
                )
            else:
                conn.settimeout(5.0)
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
