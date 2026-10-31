"""Sync regular files through a rooted protocol; no remote archive extraction."""
from __future__ import annotations
import base64
import fnmatch
import hashlib
import json
from pathlib import Path, PurePosixPath
from enclave_gateway.agents.rooted_fs import MAX_CHUNK
from enclave_gateway.operations.context import checkpoint,current


def synchronize(source, destination, source_path='', destination_path='', exclude=()):
    def excluded(path):
        return any(fnmatch.fnmatch(path,pattern) or any(fnmatch.fnmatch(part,pattern) for part in PurePosixPath(path).parts) for pattern in exclude)
    entries=source({'action':'list','path':source_path,'exclude':list(exclude)})['entries']
    prefix=source_path.rstrip('/')+'/' if source_path else ''
    import unicodedata
    identities=set()
    for entry in entries:
        identity=unicodedata.normalize('NFC',entry['path']).casefold()
        if identity in identities: raise ValueError('Tree has ambiguous cross-platform path identities')
        identities.add(identity)
    count=0; total=0; tree_hash=hashlib.sha256()
    operation=current().tx_id if current() else __import__('secrets').token_hex(16)
    for entry in entries:
        relative=entry['path'][len(prefix):]
        if excluded(relative): continue
        target=(destination_path.rstrip('/')+'/' if destination_path else '')+relative
        checkpoint('sync.entry')
        if entry['kind']=='dir':
            destination({'action':'mkdir','path':target}); continue
        stage=str(PurePosixPath(target).with_name('.egw_sync_'+hashlib.sha256((operation+target).encode()).hexdigest()))
        digest=hashlib.sha256(); offset=0
        try:
            while offset<entry['size'] or offset==0:
                checkpoint('sync.block')
                chunk=base64.b64decode(source({'action':'read','path':entry['path'],'offset':offset,'size':MAX_CHUNK})['data'],validate=True)
                if len(chunk)>MAX_CHUNK or (not chunk and offset<entry['size']): raise ValueError('Remote source changed during sync')
                destination({'action':'write','path':stage,'offset':offset,'data':base64.b64encode(chunk).decode()})
                digest.update(chunk); offset+=len(chunk)
                if offset>=entry['size']: break
            if offset!=entry['size'] or digest.hexdigest()!=entry['sha256']: raise ValueError('Source hash changed during sync')
            destination({'action':'commit','path':stage,'target':target,'sha256':digest.hexdigest(),'mode':entry.get('mode',0o600)})
        finally:
            try: destination({'action':'remove','path':stage})
            except Exception: pass
        count+=1; total+=offset; tree_hash.update((relative+'\0'+digest.hexdigest()+'\n').encode())
    return {'files_synced':count,'archive_bytes':total,'sha256':tree_hash.hexdigest(),'mode':'rooted-files'}


def remote_script(payload, windows=False, helper_path='', trusted_signers=(), require_signed=True):
    from enclave_gateway.security.quoting import ps_quote
    encoded=base64.b64encode(json.dumps(payload).encode()).decode()
    if windows:
        signers=','.join(ps_quote(item) for item in trusted_signers)
        check=f"$s=Get-AuthenticodeSignature -LiteralPath $helper; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @({signers})) {{throw 'Untrusted filesystem helper'}}" if require_signed else ''
        return f"$helper=[Environment]::ExpandEnvironmentVariables({ps_quote(helper_path)}); {check}; [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')) | & $helper fs; if ($LASTEXITCODE) {{throw 'Rooted filesystem operation failed'}}"
    import shlex
    code=(Path(__file__).parents[1]/'agents/rooted_fs.py').read_text()
    source=base64.b64encode(code.encode()).decode()
    program="import base64;exec(compile(base64.b64decode("+repr(source)+"),'<rooted-fs>','exec'))"
    return 'printf %s '+shlex.quote(encoded)+' | base64 -d | python3 -c '+shlex.quote(program)
