"""Native key-authenticated SSH from a POSIX direct controller."""
from __future__ import annotations
import base64
import hashlib
import json
import secrets
import os
import shlex
from pathlib import Path,PureWindowsPath
from enclave_gateway.agents.rooted_fs import RootedFS,MAX_CHUNK
from enclave_gateway.operations.context import budget,mark_dispatched,owned_cleanup,checkpoint
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.security.scoped_sync import remote_script
from enclave_gateway.transports.ssh_hop import SshHopExecutor,_ssh_args,_node_uri,_hash_sh


class PosixSshExecutor(SshHopExecutor):
    def _exec_plain(self,node,bash_script,*,as_root=False,ssh_password='',sudo_password='',timeout_sec=120,jump_node=None):
        if ssh_password:raise ValueError('POSIX direct SSH requires key authentication; no password argv fallback')
        if sudo_password:raise ValueError('POSIX direct sudo requires a preconfigured passwordless grant')
        windows=node.os in ('windows','win','powershell')
        if windows:
            if as_root:raise ValueError('sudo is unsupported for Windows targets')
            bootstrap='[Console]::InputEncoding=New-Object Text.UTF8Encoding($false); [Console]::OutputEncoding=New-Object Text.UTF8Encoding($false); & ([scriptblock]::Create([Console]::In.ReadToEnd())); if ($LASTEXITCODE) {exit $LASTEXITCODE}'
            remote='powershell.exe -NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(bootstrap.encode('utf-16le')).decode()
        else:remote='sudo -n sh -s' if as_root else 'sh -s'
        command=['ssh','-T',*_ssh_args(node,windows=False,jump_node=jump_node,connect_timeout_sec=max(1,min(15,int(timeout_sec)))),_node_uri(node),remote]
        data=base64.b64encode(bash_script.replace('\r\n','\n').encode()).decode()
        # DirectHostControlChannel passes this launcher through stdin as well;
        # neither the SSH argv nor the local shell argv contains the payload.
        launcher='printf %s '+shlex.quote(data)+' | base64 -d | '+shlex.join(command)
        mark_dispatched()
        return self._exec_hop(launcher,budget(timeout_sec,'ssh.exec'))

    def _file(self,node,root,payload,options):
        script=remote_script({'root':root,**payload},windows=node.os in ('windows','win','powershell'),
                             helper_path=self.runtime_helper_path,trusted_signers=self.helper_options['trusted_signers'],require_signed=self.helper_options['require_signed'])
        result=self.exec_node(node,script,**options)
        if result.exit_code:raise RuntimeError('Remote rooted file operation failed')
        value=json.loads(result.stdout)
        if 'error' in value:raise RuntimeError('Remote rooted file operation rejected')
        return value

    @staticmethod
    def location(node,path):
        if node.os in ('windows','win','powershell'):
            value=PureWindowsPath(path)
            if not value.is_absolute() or value.drive.startswith('\\\\'):raise ValueError('Use an absolute local-drive remote path')
            return value.anchor,'/'.join(value.parts[1:])
        if not path.startswith('/'):raise ValueError('Use an absolute remote path')
        return '/',path[1:]

    def push_file_to_node(self,node,local_path,remote_path,*,as_root=False,ssh_password='',sudo_password='',timeout_sec=900,jump_node=None):
        options=dict(as_root=as_root,ssh_password=ssh_password,sudo_password=sudo_password,timeout_sec=timeout_sec,jump_node=jump_node)
        root,target=self.location(node,remote_path);stage=target.rsplit('/',1)[0]+'/.egw_push_'+secrets.token_hex(16) if '/' in target else '.egw_push_'+secrets.token_hex(16)
        local=Path(local_path);digest=hashlib.sha256();offset=0
        try:
            with RootedFS(str(local.parent.resolve())) as source, source.file(local.name) as fd:
                before=os.fstat(fd)
                while True:
                    checkpoint('ssh.file.block');data=os.read(fd,MAX_CHUNK)
                    if not data and offset:break
                    self._file(node,root,{'action':'write','path':stage,'offset':offset,'data':base64.b64encode(data).decode()},options)
                    digest.update(data);offset+=len(data)
                    if len(data)<MAX_CHUNK:break
                after=os.fstat(fd)
                if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or offset!=before.st_size:
                    raise ValueError('Local source changed during transfer')
            self._file(node,root,{'action':'commit','path':stage,'target':target,'sha256':digest.hexdigest()},options)
            return digest.hexdigest()
        finally:
            try:
                with owned_cleanup():self._file(node,root,{'action':'remove','path':stage},{**options,'timeout_sec':2})
            except Exception:pass

    def pull_file_from_node(self,node,remote_path,local_path,*,as_root=False,ssh_password='',sudo_password='',timeout_sec=900,jump_node=None):
        options=dict(as_root=as_root,ssh_password=ssh_password,sudo_password=sudo_password,timeout_sec=timeout_sec,jump_node=jump_node)
        root,source=self.location(node,remote_path)
        if node.os in ('windows','win','powershell'):script="(Get-FileHash -LiteralPath "+ps_quote(remote_path)+" -Algorithm SHA256).Hash.ToLowerInvariant()"
        else:script=_hash_sh(remote_path)+'\nprintf %s "$sha"'
        result=self.exec_node(node,script,**options)
        expected=result.stdout.strip()
        if result.exit_code or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):raise ValueError('Remote source checksum is unavailable')
        local=Path(local_path);local.parent.mkdir(parents=True,exist_ok=True);stage='.egw_pull_'+secrets.token_hex(16);digest=hashlib.sha256();offset=0
        with RootedFS(str(local.parent.resolve())) as destination:
            try:
                while True:
                    checkpoint('ssh.file.block')
                    data=base64.b64decode(self._file(node,root,{'action':'read','path':source,'offset':offset,'size':MAX_CHUNK},options)['data'],validate=True)
                    if len(data)>MAX_CHUNK:raise ValueError('Remote read exceeds block limit')
                    destination.write(stage,offset,data);digest.update(data);offset+=len(data)
                    if len(data)<MAX_CHUNK:break
                if digest.hexdigest()!=expected:raise ValueError('Remote source changed during transfer')
                destination.commit(stage,local.name,expected)
                return expected
            finally:destination.remove(stage)
