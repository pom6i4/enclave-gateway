"""Index child reports without creating a root report/inventory hash cycle."""
from __future__ import annotations
import hashlib


def report_inventory(root):
    excluded={'seed','driver-media','controller','tpm','source','python-source','unpacked','obj','bin'}
    result={}
    for path in root.rglob('*'):
        if not path.is_file() or path.is_symlink() or path.suffix not in ('.json','.log'):continue
        if path in (root/'result.json',root/'inventory.json') or path.name=='credentials.json':continue
        if set(path.relative_to(root).parts)&excluded:continue
        h=hashlib.sha256()
        with path.open('rb') as f:
            for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
        result[path.relative_to(root).as_posix()]=h.hexdigest()
    return result
