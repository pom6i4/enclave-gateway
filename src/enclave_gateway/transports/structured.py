"""Structured foreground system-OpenSSH dispatch through RDP."""
from __future__ import annotations
import hashlib
import secrets
import time
from pathlib import Path

from enclave_gateway.operations.context import (
    OperationContext, OperationError, activate, budget, current, principal, read_only_preflight, timed,
)
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, generate_tx_id
from enclave_gateway.transports.ssh_hop import SshHopExecutor
from enclave_gateway.transports.stream_frames import MAX_UPLOAD_ATTACHMENT


class StructuredTransport(RdpVfsTransport):
    def request(self, op, timeout_sec=120, *, attachment=None, **fields):
        tx_id=generate_tx_id()
        if op in ('attest','ping'):
            tx_id='probe_'+tx_id
        envelope={'tx_id':tx_id,'op':op,'timeout_ms':max(1,int(budget(timeout_sec)*1000))}
        context=current()
        if context:envelope['operation_id']=context.tx_id
        if set(fields)&set(envelope):raise ValueError('Reserved envelope fields cannot be overridden')
        return self._dispatch_envelope({**envelope,**fields},timeout_sec,attachment=attachment)

    def exec_bastion(self, ps_script, timeout_sec=120, *, op='exec', extra_fields=None):
        if op not in ('attest','stop') or ps_script:
            raise OperationError('structured_operation_denied','vfs.dispatch',node='@bastion',
                                 message='structured_only does not execute PowerShell on Bastion. Use a TargetNode or an approved declarative operation.')
        if op=='stop' and (extra_fields or {}).get('unregister_autostart'):
            raise ValueError('structured_only has no autostart registration; use the offline recovery command for an older installation')
        return self.request(op,timeout_sec,**(extra_fields or {}))

    def attest(self, nonce, timeout_sec=10):
        with timed('attestation'), read_only_preflight():
            if self.spec.structured_backend != "operator":
                return super().attest(nonce, timeout_sec)
            timeout = min(budget(timeout_sec, "attestation"), 10.0)
            parent = current()
            scope = OperationContext(parent.tx_id if parent else generate_tx_id(), "@bastion",
                                     principal(), time.monotonic() + timeout)
            if parent:
                scope.cancelled = parent.cancelled
                scope.deadline = min(parent.deadline, scope.deadline)
            with activate(scope):
                return super().attest(nonce, timeout)

    def ping(self, timeout_sec=45):return self.request('ping',timeout_sec)
    def clean(self, timeout_sec=45):return self.request('clean',timeout_sec)

    def mux_open(self, *args, **kwargs):
        raise OperationError('structured_operation_denied','mux.open',message='TCP mux is unavailable in structured_only; no legacy fallback is permitted.')

    def push_file(self, *args, **kwargs):
        raise OperationError('structured_operation_denied','vfs.upload',message='Direct Bastion file access is unavailable in structured_only. Select an approved TargetNode.')

    def pull_file(self, *args, **kwargs):
        raise OperationError('structured_operation_denied','vfs.download',message='Direct Bastion file access is unavailable in structured_only. Select an approved TargetNode.')


class StructuredSshExecutor(SshHopExecutor):
    def __init__(self, transport, control, spec, *, owned_commands=False):
        self.transport,self.control,self.spec=transport,control,spec
        self.owned_commands=owned_commands
        self.security_mode='standard'
        self.helper_options={'helper_path':'','trusted_signers':(),'require_signed':True}

    def _authentication(self,node,password,jump_node):
        return "",jump_node

    def _validate(self,node,options):
        if node.os not in ('linux','posix','unix') or options.get('jump_node'):
            raise ValueError('structured_only supports direct Linux TargetNodes through the approved Bastion policy')
        if options.get('ssh_password') or options.get('sudo_password'):
            raise ValueError('structured_only requires approved SSH keys and noninteractive sudo; password helpers are unavailable')

    @staticmethod
    def _identity(node):return {'expected_host':node.host,'expected_port':node.port,'expected_user':node.user}

    def _exec_plain(self,node,bash_script,**options):
        self._validate(node,options)
        with timed('ssh.exec'):
            return self.transport.request('ssh_exec',options.get('timeout_sec',120),target=node.name,
                                          command=bash_script,as_root=bool(options.get('as_root')),**self._identity(node))

    def push_file_to_node(self,node,local_path,remote_path,**options):
        self._validate(node,options)
        token=secrets.token_hex(16)
        path=self.spec.appliance_spool_dir.rstrip('\\/')+'\\structured_'+token+'.bin'
        source=Path(local_path)
        size=source.stat().st_size
        if size>64*1024*1024:raise ValueError('structured_only transfer limit is 64 MiB')
        from enclave_gateway.transports.rdp_vfs import compute_file_sha256
        attachment=None
        if self.spec.structured_backend == "operator":
            evidence=self.transport._verify_dispatch("ssh_push")
            if evidence and evidence.get("stream_upload_v1") is True and 0 < size <= MAX_UPLOAD_ATTACHMENT:
                with source.open("rb") as stream:
                    attachment=stream.read(MAX_UPLOAD_ATTACHMENT+1)
                if len(attachment)!=size:
                    raise ValueError("The upload source changed size while reading")
        digest=hashlib.sha256(attachment).hexdigest() if attachment is not None else compute_file_sha256(source)
        completed=False
        try:
            if attachment is None:
                self.control.write_file(source,path)
            result=self.transport.request('ssh_push',options.get('timeout_sec',900),target=node.name,
                        attachment=attachment,transfer_id=token,remote_path=remote_path,sha256=digest,
                        as_root=bool(options.get('as_root')),**self._identity(node))
            if result.exit_code or result.stdout.strip()!='VERIFIED:'+digest:
                raise OperationError('structured_transfer_failed','ssh.upload',indeterminate=True,message='Transfer was not verified; reconcile its transaction before retrying.')
            completed=True
            return digest
        finally:
            if completed and attachment is None:self.control.consume_file(path)

    def pull_file_from_node(self,node,remote_path,local_path,**options):
        self._validate(node,options)
        token=secrets.token_hex(16)
        path=self.spec.appliance_spool_dir.rstrip('\\/')+'\\structured_'+token+'.bin'
        completed=False
        try:
            result=self.transport.request('ssh_pull',options.get('timeout_sec',900),target=node.name,
                        transfer_id=token,remote_path=remote_path,as_root=bool(options.get('as_root')),**self._identity(node))
            expected=result.stdout.strip().removeprefix('SHA256:')
            if result.exit_code or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
                raise OperationError('structured_transfer_failed','ssh.download',indeterminate=True)
            destination=Path(local_path);destination.parent.mkdir(parents=True,exist_ok=True)
            temporary=destination.with_name('.'+destination.name+'.egw-'+token)
            try:
                self.control.read_file(path,temporary)
                from enclave_gateway.transports.rdp_vfs import compute_file_sha256
                if compute_file_sha256(temporary)!=expected:raise ValueError('Download checksum mismatch')
                temporary.replace(destination)
            finally:temporary.unlink(missing_ok=True)
            completed=True
            return expected
        finally:
            if completed:self.control.consume_file(path)

    def bootstrap_ssh_key(self,*args,**kwargs):
        raise ValueError('Approve the SSH key and host fingerprint on Bastion before using structured_only')
