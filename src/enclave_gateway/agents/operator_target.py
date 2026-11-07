"""Linux-side forced command for an administrator-approved operator SSH key.

Run this file with Python 3.10+ using sshd ForceCommand or an authorized_keys
command restriction. The Windows adapter performs the target and operation
checks. This SSH key grants the account's shell privileges by design.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time

MAX_HEADER = 2 * 1024 * 1024
MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = MAX_INPUT + 100
MAX_ERROR = 1024 * 1024
READY = b"EGWSSH1\n"


def _read_exact(source, length):
    data = source.read(length)
    if len(data) != length:
        raise EOFError("Incomplete operator request")
    return data


def _request(source, size):
    if not re.fullmatch(rb"[0-9a-f]{8}", size) or not 2 <= int(size, 16) <= MAX_HEADER:
        raise ValueError("Invalid operator request header length")
    request = json.loads(_read_exact(source, int(size, 16)))
    if (
        not isinstance(request, dict)
        or set(request) != {"id", "command", "input_bytes", "output_limit", "timeout_ms"}
        or not isinstance(request["id"], str)
        or not re.fullmatch(r"[A-Za-z0-9_]{1,128}", request["id"])
        or not isinstance(request["command"], str)
        or not request["command"]
        or "\0" in request["command"]
        or type(request["input_bytes"]) is not int
        or not 0 <= request["input_bytes"] <= MAX_INPUT
        or type(request["output_limit"]) is not int
        or not 1 <= request["output_limit"] <= MAX_OUTPUT
        or type(request["timeout_ms"]) is not int
        or not 1 <= request["timeout_ms"] <= 15_000
    ):
        raise ValueError("Invalid operator request")
    return request


def _execute(command, payload, output_limit, deadline, session=None):
    if time.monotonic() >= deadline:
        return 125, b"", b"Expired before Linux dispatch\n", False
    process = subprocess.Popen(
        ["/bin/sh", "-c", command],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, bufsize=0,
    )
    buffers = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: output_limit, process.stderr: MAX_ERROR}
    position = 0
    try:
        with selectors.DefaultSelector() as selector:
            if session is not None:
                selector.register(session, selectors.EVENT_READ)
            for stream in buffers:
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            if payload:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            else:
                process.stdin.close()
            while len(selector.get_map()) > int(session is not None):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                for key, _ in selector.select(remaining):
                    stream = key.fileobj
                    if stream is session:
                        # The adapter permits one in-flight command. Any further
                        # input or EOF before a reply retires this SSH connection.
                        raise EOFError("SSH session interrupted")
                    if stream is process.stdin:
                        try:
                            position += os.write(key.fd, payload[position:position + 65536])
                        except BrokenPipeError:
                            position = len(payload)
                        if position == len(payload):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(stream)
                        else:
                            if len(buffers[stream]) + len(block) > limits[stream]:
                                raise ValueError("Linux command output limit exceeded")
                            buffers[stream].extend(block)
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        return code if code >= 0 else 128 - code, buffers[process.stdout], buffers[process.stderr], False
    except (TimeoutError, subprocess.TimeoutExpired, ValueError):
        return 125, b"", b"Linux command interrupted; reconcile its effects\n", True
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def serve(source, sink):
    sink.write(READY)
    sink.flush()
    while size := source.read(8):
        request = _request(source, size)
        deadline = time.monotonic() + request["timeout_ms"] / 1000
        payload = _read_exact(source, request["input_bytes"])
        code, stdout, stderr, unknown = _execute(
            request["command"], payload, request["output_limit"], deadline,
            session=source if source is sys.stdin.buffer else None,
        )
        header = json.dumps({
            "id": request["id"], "exit_code": code, "output_bytes": len(stdout),
            "error_bytes": len(stderr), "indeterminate": unknown,
        }, separators=(",", ":")).encode("ascii")
        for part in (f"{len(header):08x}".encode("ascii"), header, stdout, stderr):
            sink.write(part)
        sink.flush()
        if unknown:
            return


if __name__ == "__main__":
    # Do not enable this endpoint for existing multipurpose SSH credentials.
    if os.environ.get("SSH_ORIGINAL_COMMAND") != "egw-operator-v1":
        sys.exit("Expected the approved Enclave Gateway SSH command")
    try:
        serve(sys.stdin.buffer, sys.stdout.buffer)
    except (OSError, ValueError, EOFError, RecursionError):
        sys.exit("Operator SSH protocol failed; reconcile any dispatched operation")
