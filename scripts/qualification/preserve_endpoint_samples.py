#!/usr/bin/env python3
"""Preserve approved worker/policy bytes on the Host before endpoint execution.

No process is launched and no signature or antivirus verdict is inferred.
The output is private incident evidence, not a public support export.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


MAX_SAMPLE_BYTES = 16 * 1024 * 1024
MANIFEST_NAME = 'manifest.json'
FILENAMES = {'worker.ps1', 'policy.json', MANIFEST_NAME}


def approved_hash(value: str) -> str:
    if not re.fullmatch(r'[a-fA-F0-9]{64}', value):
        raise ValueError('An independently approved SHA-256 is required')
    return value.lower()


def private_mode(metadata: os.stat_result) -> None:
    if os.name == 'posix':
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('Evidence must be owned by the current user with no group/other access')


def read_regular(path: Path, limit: int, *, private: bool = False) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Only regular files without reparse points are accepted')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError('Source identity changed while opening')
        if private:
            private_mode(opened)
        if opened.st_size > limit:
            raise ValueError('Evidence file exceeds the size limit')
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(data) > limit:
            raise ValueError('Evidence file exceeds the size limit')
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('Source changed during capture')
    return data


def write_new(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def file_record(data: bytes) -> dict:
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)}


def verify_bundle(bundle: Path, worker_sha256: str, policy_sha256: str) -> dict:
    pins = {'worker.ps1': approved_hash(worker_sha256), 'policy.json': approved_hash(policy_sha256)}
    metadata = bundle.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or getattr(metadata, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Evidence bundle must be a directory without a reparse point')
    private_mode(metadata)
    if {entry.name for entry in bundle.iterdir()} != FILENAMES:
        raise ValueError('Incomplete bundle or unexpected evidence files')
    manifest = json.loads(read_regular(bundle / MANIFEST_NAME, 65536, private=True))
    if (not isinstance(manifest, dict)
            or manifest.get('schema') != 'egw.endpoint-samples.v1'
            or manifest.get('status') != 'complete'
            or manifest.get('authenticode_verification') != 'not_performed'
            or manifest.get('kes_acceptance') != 'not_performed'
            or not isinstance(manifest.get('files'), dict)
            or set(manifest['files']) != set(pins)):
        raise ValueError('Invalid evidence manifest')
    for name, expected in pins.items():
        record = file_record(read_regular(bundle / name, MAX_SAMPLE_BYTES, private=True))
        if record['sha256'] != expected or record != manifest['files'][name]:
            raise ValueError('Evidence differs from the approved SHA-256 or manifest')
    return manifest


def capture(worker: Path, worker_sha256: str, policy: Path, policy_sha256: str, output: Path) -> dict:
    pins = {'worker.ps1': approved_hash(worker_sha256), 'policy.json': approved_hash(policy_sha256)}
    sources = {'worker.ps1': worker, 'policy.json': policy}
    samples = {}
    for name, path in sources.items():
        if path.suffix.lower() != Path(name).suffix:
            raise ValueError('Supply only the approved .ps1 worker and .json policy')
        data = read_regular(path, MAX_SAMPLE_BYTES)
        if file_record(data)['sha256'] != pins[name]:
            raise ValueError('Source differs from the independently approved SHA-256')
        samples[name] = data

    # Resolve only the parent; an existing output or output symlink must fail mkdir.
    parent = output.parent.resolve(strict=True)
    private_mode(parent.stat())
    output = parent / output.name
    output.mkdir(mode=0o700)
    try:
        for name, data in samples.items():
            write_new(output / name, data)
            if read_regular(output / name, MAX_SAMPLE_BYTES, private=True) != data:
                raise ValueError('Sample readback failed')
        manifest = {
            'schema': 'egw.endpoint-samples.v1',
            'status': 'complete',
            'captured_utc': datetime.now(timezone.utc).isoformat(),
            'authenticode_verification': 'not_performed',
            'kes_acceptance': 'not_performed',
            'posix_permissions_checked': os.name == 'posix',
            'windows_acl_verification': 'not_performed',
            'files': {name: file_record(data) for name, data in samples.items()},
        }
        write_new(output / MANIFEST_NAME, (json.dumps(manifest, indent=2) + '\n').encode('utf-8'))
        result = verify_bundle(output, worker_sha256, policy_sha256)
        if os.name == 'posix':
            descriptor = os.open(output, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return result
    except BaseException as error:
        # Never remove a failed capture or turn it into a complete bundle.
        try:
            write_new(output / 'capture-failure.json', json.dumps({'status': 'failed', 'error_type': type(error).__name__}).encode('utf-8'))
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    save = commands.add_parser('capture', help='Preserve exact approved bytes in a new private directory')
    save.add_argument('--worker', type=Path, required=True)
    save.add_argument('--policy', type=Path, required=True)
    save.add_argument('--output', type=Path, required=True)
    check = commands.add_parser('verify', help='Recheck saved bytes against independent approved hashes')
    check.add_argument('--bundle', type=Path, required=True)
    for command in (save, check):
        command.add_argument('--worker-sha256', required=True)
        command.add_argument('--policy-sha256', required=True)
    arguments = parser.parse_args()
    try:
        if arguments.operation == 'capture':
            result = capture(arguments.worker, arguments.worker_sha256, arguments.policy, arguments.policy_sha256, arguments.output)
        else:
            result = verify_bundle(arguments.bundle, arguments.worker_sha256, arguments.policy_sha256)
    except (OSError, ValueError) as error:
        # Paths and source contents are deliberately excluded from console errors.
        message = str(error) if isinstance(error, ValueError) else 'Cannot access evidence; check storage and permissions without overwriting the attempt'
        print(json.dumps({'status': 'failed', 'error_type': type(error).__name__, 'message': message}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
