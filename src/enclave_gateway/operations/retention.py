"""Bound payload retention while retaining idempotency tombstones indefinitely."""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RetentionPolicy:
    max_age_seconds: float = 7 * 86400
    max_results: int = 10000
    max_payload_bytes: int = 64 * 1024 * 1024
    archive_seconds: float = 90 * 86400
    interval_seconds: float = 60
    max_identities: int = 1000000
    max_archive_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        import math
        if any(not math.isfinite(value) or value < 0 for value in
               (self.max_age_seconds, self.archive_seconds, self.interval_seconds)):
            raise ValueError('Retention durations must be finite and nonnegative')
        if any(type(value) is not int or value < 1 for value in
               (self.max_results, self.max_payload_bytes, self.max_identities,self.max_archive_bytes)):
            raise ValueError('Retention limits must be positive integers')


def private_directory(path: Path):
    if path.is_symlink():
        raise PermissionError('Archive directory must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != 'nt':
        if path.stat().st_uid != os.getuid():
            raise PermissionError('Archive directory has another owner')
        path.chmod(0o700)


def write_archive(directory: Path, records: list[dict]):
    private_directory(directory)
    data = b''.join(json.dumps(row, ensure_ascii=False, sort_keys=True).encode() + b'\n' for row in records)
    digest = hashlib.sha256(data).hexdigest()
    name = 'archive_' + uuid.uuid4().hex + '_' + digest + '.jsonl'
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return name


def read_archive(directory: Path, reference: str, tx_id: str, principal: str):
    if not re.fullmatch(r'archive_[a-f0-9]{32}_[a-f0-9]{64}\.jsonl', reference):
        raise ValueError('Invalid archive reference')
    path = directory / reference
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read()
    if hashlib.sha256(data).hexdigest() != reference.rsplit('_', 1)[1][:-6]:
        raise ValueError('Archive integrity mismatch')
    for line in data.splitlines():
        row = json.loads(line)
        if row['tx_id'] == tx_id and row['principal'] == principal:
            return row
    raise ValueError('Transaction absent from archive')


def maintain(journal):
    """Archive settled payloads; preserve live rows and ambiguous identity/state."""
    policy = journal.retention
    now = time.time()
    directory = journal.path.with_suffix('.archives')
    archived = 0
    with journal.connect() as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            kept_bytes = 0
            index = 0
            batch, batch_bytes = [], 0
            def flush():
                nonlocal archived, batch, batch_bytes
                if not batch: return
                reference = write_archive(directory, batch)
                for row in batch:
                    summary=None
                    if row['state']=='indeterminate' and row['error']:
                        summary={key:value for key,value in row['error'].items() if key in ('code','stage','tx_id','node','indeterminate','retryable')}
                        summary['message']='Detailed outcome archived; remote execution remains indeterminate'
                    db.execute("UPDATE transactions SET result=NULL,error=?,archive_ref=? WHERE tx_id=?", (json.dumps(summary) if summary else None,reference,row['tx_id']))
                archived += len(batch)
                batch, batch_bytes = [], 0
            # Page metadata independently of payloads, including for an old large
            # database. Only evicted results are loaded, one at a time.
            cursor = None
            while True:
                condition = '' if cursor is None else ' AND (updated<? OR (updated=? AND tx_id<?))'
                parameters = () if cursor is None else (cursor[0], cursor[0], cursor[1])
                rows = db.execute("SELECT tx_id,updated,length(CAST(COALESCE(result,'') AS BLOB))+length(CAST(COALESCE(error,'') AS BLOB)) AS bytes FROM transactions WHERE state IN ('completed','failed','cancelled','indeterminate') AND archive_ref=''"+condition+" ORDER BY updated DESC,tx_id DESC LIMIT 128", parameters).fetchall()
                if not rows: break
                for row in rows:
                    size = row['bytes']
                    if index >= policy.max_results or row['updated'] < now-policy.max_age_seconds or kept_bytes+size > policy.max_payload_bytes:
                        if batch and (len(batch)>=256 or batch_bytes+size>8*1024*1024): flush()
                        batch.append(journal.decode(db.execute('SELECT * FROM transactions WHERE tx_id=?',(row['tx_id'],)).fetchone()))
                        batch_bytes += size
                    else:
                        kept_bytes += size
                    index += 1
                cursor = (rows[-1]['updated'],rows[-1]['tx_id'])
            flush()
            db.execute('COMMIT')
        except BaseException:
            if db.in_transaction: db.execute('ROLLBACK')
            raise
    removed = 0
    if directory.exists():
        private_directory(directory)
        files=[path for path in directory.iterdir() if re.fullmatch(r'archive_[a-f0-9]{32}_[a-f0-9]{64}\.jsonl',path.name) and not path.is_symlink()]
        total=sum(path.stat().st_size for path in files)
        for path in sorted(files,key=lambda path:path.stat().st_mtime):
            info=path.stat()
            if info.st_mtime < now-policy.archive_seconds or total>policy.max_archive_bytes:
                path.unlink(); removed+=1; total-=info.st_size
    return {'archived_results':archived,'removed_archives':removed,'identities_preserved':True}
