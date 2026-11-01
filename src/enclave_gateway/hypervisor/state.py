"""Offline, integrity-checked VM state bundles and recoverable replacement."""
from __future__ import annotations
import contextlib
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from enclave_gateway.control.qga_client import _file_lock


def digest(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):value.update(block)
    return value.hexdigest()


def sync_dir(path):
    if os.name=='nt':return
    fd=os.open(path,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def private_dir(path):
    if path.is_symlink():raise ValueError('State directory must not be a symlink')
    path.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name=='nt':
        from enclave_gateway.security.windows_acl import protect_directory
        protect_directory(path)
    if os.name!='nt' and (path.stat().st_uid!=os.getuid() or path.stat().st_mode & 0o077):
        raise PermissionError('State directory must be private and owned by this user')


def inventory(path):
    if path.is_symlink():raise ValueError('State links are unsupported')
    if path.is_file():
        info=path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('State must be single-link regular files')
        return {'':{'sha256':digest(path),'bytes':info.st_size}}
    if not path.is_dir():raise FileNotFoundError('VM state resource is missing')
    files={}
    for item in sorted(path.rglob('*')):
        if item.is_symlink():raise ValueError('State links are unsupported')
        if item.is_dir():continue
        relative=item.relative_to(path).as_posix()
        files[relative]=inventory(item)['']
        if len(files)>256:raise ValueError('Too many TPM state files')
    return files


def copy_resource(source,destination):
    if source.is_dir():
        shutil.copytree(source,destination)
        destination.chmod(0o700)
    else:
        # macOS/APFS clones keep large offline VM replacement affordable.
        # Other platforms use a regular independent copy, never a hard link.
        if __import__('sys').platform=='darwin':
            result=subprocess.run(['/bin/cp','-c',str(source),str(destination)],capture_output=True)
            if result.returncode:shutil.copyfile(source,destination)
        else:shutil.copyfile(source,destination)
    for file in ([destination] if destination.is_file() else destination.rglob('*')):
        if file.is_file():
            file.chmod(0o600)
            with file.open('r+b') as stream:os.fsync(stream.fileno())
    sync_dir(destination.parent)


def atomic_json(path,value):
    temporary=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    try:
        with temporary.open('x',encoding='utf-8') as stream:
            if os.name!='nt':os.fchmod(stream.fileno(),0o600)
            json.dump(value,stream,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path);sync_dir(path.parent)
    finally:temporary.unlink(missing_ok=True)


def remove_resource(path):
    if path.is_symlink():raise ValueError('Unexpected state link')
    if path.is_dir():shutil.rmtree(path)
    else:path.unlink(missing_ok=True)


class StateStore:
    def __init__(self,spec,firmware):
        self.spec=spec;self.firmware=Path(firmware)
        self.targets={'disk':Path(spec.disk_path).expanduser().absolute(),
                      'nvram':Path(spec.efi_vars_path).expanduser().absolute()}
        if spec.tpm_state_dir:self.targets['tpm']=Path(spec.tpm_state_dir).expanduser().absolute()
        resolved=[p.resolve() for p in self.targets.values()]
        if len(set(resolved))!=len(resolved) or any(a in b.parents for a in resolved for b in resolved if a!=b):
            raise ValueError('VM state resources must be distinct and non-overlapping')
        self.root=Path(spec.snapshot_dir).expanduser().absolute() if spec.snapshot_dir else self.targets['disk'].with_suffix('.states')
        if any(self.root.resolve()==p or p in self.root.resolve().parents or self.root.resolve() in p.parents for p in resolved):
            raise ValueError('State store must not overlap VM resources')
        self.pending=self.root/'pending-restore.json'

    @contextlib.contextmanager
    def locked(self):
        private_dir(self.root)
        with _file_lock(self.root/'operation.lock',30):yield self

    def identity(self):
        return hashlib.sha256(json.dumps({k:str(v) for k,v in self.targets.items()},sort_keys=True).encode()).hexdigest()

    def compatibility(self):
        return {'arch':self.spec.arch,'firmware_sha256':digest(self.firmware),'resources':sorted(self.targets)}

    def backing_inventory(self,executable):
        chain=json.loads(subprocess.check_output([executable,'info','--backing-chain','--output=json',str(self.targets['disk'])]))
        if not isinstance(chain,list) or not 1<=len(chain)<=32:raise ValueError('Unsupported disk backing chain')
        files={}
        for image in chain[:-1]:
            path=Path(image['full-backing-filename'])
            if not path.is_absolute():raise ValueError('Backing image path must be absolute')
            files[str(path)]=inventory(path)
        return files

    @staticmethod
    def name(value):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',value):raise ValueError('Invalid state bundle name')
        return value

    def create(self,name):
        name=self.name(name);destination=self.root/name
        if destination.exists():raise FileExistsError('State bundle already exists')
        if self.pending.exists():raise RuntimeError('Recover the interrupted restore first')
        stage=self.root/('.create-'+uuid.uuid4().hex);stage.mkdir(mode=0o700)
        try:
            before={k:inventory(p) for k,p in self.targets.items()}
            executable=shutil.which('qemu-img')
            if not executable:raise FileNotFoundError('qemu-img is required')
            backing_before=self.backing_inventory(executable)
            subprocess.run([executable,'convert','-f','qcow2','-O','qcow2',str(self.targets['disk']),str(stage/'disk')],check=True,capture_output=True)
            subprocess.run([executable,'check','-q','-f','qcow2',str(stage/'disk')],check=True,capture_output=True)
            for kind,path in self.targets.items():
                if kind!='disk':copy_resource(path,stage/kind)
            after={k:inventory(p) for k,p in self.targets.items()}
            if before!=after or backing_before!=self.backing_inventory(executable):raise RuntimeError('VM state changed during offline capture')
            manifest={'revision':1,'kind':'consistent-offline-state','compatibility':self.compatibility(),
                      'files':{k:inventory(stage/k) for k in self.targets}}
            for kind in self.targets:
                if (stage/kind).is_file():
                    (stage/kind).chmod(0o600)
                    with (stage/kind).open('r+b') as stream:os.fsync(stream.fileno())
            atomic_json(stage/'manifest.json',manifest);sync_dir(stage)
            os.replace(stage,destination);sync_dir(self.root)
            return manifest
        finally:
            if stage.exists():shutil.rmtree(stage)

    def verify(self,name):
        bundle=self.root/self.name(name)
        if bundle.is_symlink():raise ValueError('State bundle cannot be a link')
        manifest=json.loads((bundle/'manifest.json').read_text())
        if manifest.get('revision')!=1 or manifest.get('kind')!='consistent-offline-state' or manifest.get('compatibility')!=self.compatibility():
            raise ValueError('Incompatible state bundle')
        if set(manifest.get('files',{}))!=set(self.targets):raise ValueError('Incomplete VM state bundle')
        if set(p.name for p in bundle.iterdir())!=set(self.targets)|{'manifest.json'}:raise ValueError('Unexpected state bundle contents')
        for kind in self.targets:
            if inventory(bundle/kind)!=manifest['files'][kind]:raise ValueError('State bundle integrity failure')
        return bundle,manifest

    def workspaces(self,token):
        if not re.fullmatch(r'[0-9a-f]{32}',token):raise ValueError('Invalid restore identity')
        return {kind:path.parent/('.egw-restore-'+token+'-'+kind) for kind,path in self.targets.items()}

    def recover(self):
        if not self.pending.exists():return False
        operation=json.loads(self.pending.read_text())
        if operation.get('revision')!=1 or operation.get('identity')!=self.identity():raise ValueError('Restore recovery identity mismatch')
        if set(operation.get('before',{}))!=set(self.targets) or set(operation.get('after',{}))!=set(self.targets):raise ValueError('Incomplete recovery metadata')
        work=self.workspaces(operation['token'])
        # Validate every rollback candidate before replacing any current state.
        for kind,target in self.targets.items():
            old=work[kind]/'old'
            if old.exists():
                if inventory(old)!=operation['before'][kind]:raise ValueError('Rollback integrity failure')
                if target.exists() and inventory(target)!=operation['after'][kind]:raise RuntimeError('Current state changed since interrupted restore')
            elif inventory(target)!=operation['before'][kind]:raise RuntimeError('Previous VM state is unavailable')
        for kind,target in self.targets.items():
            old=work[kind]/'old'
            if old.exists():
                # Preserve the new generation until the old generation is back.
                if target.exists():os.replace(target,work[kind]/'discard')
                os.replace(old,target);sync_dir(target.parent)
        self.pending.unlink();sync_dir(self.root)
        for path in work.values():
            if path.exists():shutil.rmtree(path)
        return True

    def restore(self,name):
        self.recover();bundle,manifest=self.verify(name)
        token=uuid.uuid4().hex;work=self.workspaces(token);pending_written=False
        operation={'revision':1,'identity':self.identity(),'token':token,
                   'before':{k:inventory(p) for k,p in self.targets.items()},'after':manifest['files']}
        try:
            for kind,path in work.items():
                private_dir(path);copy_resource(bundle/kind,path/'new')
                if inventory(path/'new')!=manifest['files'][kind]:raise ValueError('Staged restore integrity failure')
            # Persist intent before the first rename. Startup recovers this intent
            # under the same state lock before allowing a guest to run.
            atomic_json(self.pending,operation);pending_written=True
            for kind,target in self.targets.items():
                os.replace(target,work[kind]/'old');sync_dir(target.parent)
                os.replace(work[kind]/'new',target);sync_dir(target.parent)
            self.pending.unlink();sync_dir(self.root);pending_written=False
        except BaseException:
            if pending_written:self.recover()
            raise
        finally:
            if not self.pending.exists():
                for path in work.values():
                    if path.exists():shutil.rmtree(path)
        return manifest
