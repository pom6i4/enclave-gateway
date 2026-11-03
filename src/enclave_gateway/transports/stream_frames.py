"""Bounded committed frames for an explicitly selected redirected-file stream.

SHA-256 detects incomplete/corrupt publication; it is not authentication. The
spool ACL and the existing worker attestation remain the security boundary.
"""
from __future__ import annotations
import base64
import hashlib
import json
import math
import re

MAGIC = b"EGWS1 "
MAX_BODY = 1024 * 1024
MAX_FRAME = len(MAGIC) + 65 + ((MAX_BODY + 2) // 3) * 4 + 1
MAX_STREAM = 64 * 1024 * 1024
CONTROL_RESERVE = 1024 * 1024
BLOCK = 4096
REVISION = 3


def _flat(value):
    # Protocol envelopes contain scalar fields; scripts, binary data and nested
    # attestation evidence travel inside Base64 strings, never object graphs.
    return isinstance(value, dict) and all(
        isinstance(key, str) and type(item) in (str, int, float, bool, type(None))
        and (type(item) is not float or math.isfinite(item))
        for key, item in value.items())


def encode_frame(value):
    if not _flat(value):
        raise ValueError("Stream envelopes must be flat JSON objects with finite scalar fields")
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(body) > MAX_BODY:
        raise ValueError("Stream envelope exceeds 1 MiB; select bastion.spool_protocol: files for larger commands")
    return MAGIC + hashlib.sha256(body).hexdigest().encode() + b" " + base64.b64encode(body) + b"\n"


def request_block(data, position, limit):
    """Align immutable request starts so response handles can be prepared ahead."""
    if type(position) is not int or not 0 <= position <= limit:
        raise ValueError("Invalid request stream position")
    start = (position + BLOCK - 1) // BLOCK * BLOCK
    end = (start + len(data) + BLOCK - 1) // BLOCK * BLOCK
    if end > limit:
        raise ValueError("Stream capacity reached; stop the worker and archive its spool")
    return start, bytes(start-position) + data + bytes(end-start-len(data))


class Decoder:
    """Incremental, bounded decoder retaining absolute spans for targeted erasure."""
    def __init__(self, offset=0):
        self.buffer = bytearray()
        self.offset = offset

    def feed(self, data):
        self.buffer.extend(data)
        frames = []
        while self.buffer:
            start = self.buffer.find(MAGIC)
            if start < 0:
                keep = min(len(MAGIC)-1, len(self.buffer))
                self.offset += len(self.buffer)-keep
                del self.buffer[:len(self.buffer)-keep]
                break
            self.offset += start
            del self.buffer[:start]
            end = self.buffer.find(b"\n")
            if end < 0:
                if len(self.buffer) > MAX_FRAME:
                    self.offset += len(MAGIC)
                    del self.buffer[:len(MAGIC)]
                    continue
                break
            next_marker = self.buffer.find(MAGIC, len(MAGIC))
            if 0 <= next_marker < end:
                self.offset += next_marker
                del self.buffer[:next_marker]
                continue
            raw = bytes(self.buffer[:end+1])
            position = self.offset
            del self.buffer[:end+1]
            self.offset += end+1
            if len(raw) > MAX_FRAME:
                continue
            try:
                digest, encoded = raw[len(MAGIC):-1].split(b" ", 1)
                if not re.fullmatch(b"[0-9a-f]{64}", digest):
                    continue
                body = base64.b64decode(encoded, validate=True)
                if len(body) > MAX_BODY or hashlib.sha256(body).hexdigest().encode() != digest:
                    continue
                value = json.loads(body.decode("utf-8"))
                if _flat(value):
                    frames.append((position, len(raw), value))
            except (ValueError, UnicodeError, RecursionError):
                continue
        return frames


def descriptor(raw):
    value = json.loads(raw.decode("utf-8-sig"))
    if (not isinstance(value, dict) or type(value.get("revision")) is not int or value.get("revision") != REVISION
            or type(value.get("block_bytes")) is not int or value["block_bytes"] != BLOCK
            or not isinstance(value.get("instance"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", value["instance"])
            or not isinstance(value.get("worker_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["worker_sha256"])):
        raise ValueError("Invalid stream descriptor; restart the selected worker")
    return value
