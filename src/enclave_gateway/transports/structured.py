"""Structured foreground system-OpenSSH dispatch through RDP."""
from __future__ import annotations
import hashlib
import os
import re
import secrets
import time
from pathlib import Path
from tempfile import NamedTemporaryFile

from enclave_gateway.operations.context import (
    OperationContext, OperationError, activate, budget, checkpoint, current, limit_deadline, principal,
    read_only_preflight, timed,
)
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport, generate_tx_id
from enclave_gateway.transports.ssh_hop import SshHopExecutor
from enclave_gateway.transports.stream_frames import MAX_UPLOAD_ATTACHMENT

DOWNLOAD_PART_BYTES = 1024 * 1024
UPLOAD_PART_BYTES = MAX_UPLOAD_ATTACHMENT
MAX_CHUNKED_COPY_BYTES = 512 * DOWNLOAD_PART_BYTES


class StructuredTransport(RdpVfsTransport):
    def request(self, op, timeout_sec=120, *, attachment=None, download=None, **fields):
        tx_id=generate_tx_id()
        if op in ('attest','ping'):
            tx_id='probe_'+tx_id
        envelope={'tx_id':tx_id,'op':op,'timeout_ms':max(1,int(budget(timeout_sec)*1000))}
        context=current()
        if context:envelope['operation_id']=context.tx_id
        if set(fields)&set(envelope):raise ValueError('Reserved envelope fields cannot be overridden')
        return self._dispatch_envelope({**envelope,**fields},timeout_sec,attachment=attachment,download=download)

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

    def copy_chunked(self, direction, node, local_path, remote_path, *, timeout_sec, as_root, **options):
        self._validate(node, options)
        if direction not in ("push", "pull"):
            raise ValueError("Chunked copy direction must be push or pull")
        if not remote_path.startswith("/") or remote_path.endswith("/") or any(c in remote_path for c in "\r\n\0"):
            raise ValueError("Chunked copy requires an absolute remote file path")
        evidence = self.transport._verify_dispatch("ssh_copy")
        if not evidence or evidence.get("chunked_copy_slots_v1") is not True:
            raise OperationError("chunked_copy_unavailable", "attestation",
                                 message="Start an approved signed operator worker that supports chunked copy.")
        copy = self._push_chunked if direction == "push" else self._pull_chunked
        return copy(local_path, node, remote_path, timeout_sec, as_root)

    def _copy_step(self, node, remote_path, timeout_sec, as_root, action, token, **fields):
        with limit_deadline(min(timeout_sec, 15.0)):
            result = self.transport.request(
                "ssh_copy", min(timeout_sec, 15.0), target=node.name, remote_path=remote_path,
                as_root=as_root, transfer_id=token, copy_action=action, **self._identity(node), **fields,
            )
            checkpoint("ssh." + action)
        if result.exit_code:
            raise OperationError(
                "structured_transfer_failed", "ssh." + action,
                indeterminate=action == "push_commit",
                message=f"Chunked copy failed at {action} ({token}). Inspect the worker journal and approved transfer policy.",
            )
        return result.stdout.strip()

    def _push_chunked(self, source, node, remote_path, timeout_sec, as_root):
        if not source.is_file():
            raise FileNotFoundError(f"Local file not found: {source}")
        token = secrets.token_hex(16)
        digest = hashlib.sha256()
        with source.open("rb") as stream:
            initial = os.fstat(stream.fileno())
            size = initial.st_size
            if size > MAX_CHUNKED_COPY_BYTES:
                raise ValueError("Chunked copy limit is 512 MiB")
            for offset in range(0, max(size, 1), UPLOAD_PART_BYTES):
                checkpoint("ssh.push_part")
                count = min(UPLOAD_PART_BYTES, size - offset)
                part = stream.read(count)
                if len(part) != count:
                    raise ValueError("Upload source changed during chunked copy")
                digest.update(part)
                part_hash = hashlib.sha256(part).hexdigest()
                reply = self._copy_step(node, remote_path, timeout_sec, as_root, "push_part", token,
                                        copy_offset=offset, copy_length=count, sha256=part_hash, attachment=part or None)
                if reply != f"PART:{part_hash}":
                    raise OperationError("structured_transfer_failed", "ssh.push_part", indeterminate=True,
                                         message=f"Upload block receipt is invalid ({token}). Reconcile before retrying.")
            final = os.fstat(stream.fileno())
            if (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
                    final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                raise ValueError("Upload source changed during chunked copy")
        expected = digest.hexdigest()
        reply = self._copy_step(node, remote_path, timeout_sec, as_root, "push_commit", token,
                                copy_offset=size, sha256=expected)
        if reply != f"VERIFIED:{expected}":
            raise OperationError("structured_transfer_failed", "ssh.push_commit", indeterminate=True,
                                 message=f"Upload commit receipt is invalid ({token}). Reconcile before retrying.")
        return expected

    def _pull_chunked(self, destination, node, remote_path, timeout_sec, as_root):
        info = self._copy_step(node, remote_path, timeout_sec, as_root, "pull_info", secrets.token_hex(16))
        metadata = re.fullmatch(r"FILE:([0-9]{1,9}):([a-f0-9]{64})", info)
        if metadata is None:
            raise ValueError("Invalid chunked download metadata")
        size, expected = int(metadata[1]), metadata[2]
        if size > MAX_CHUNKED_COPY_BYTES:
            raise ValueError("Chunked copy limit is 512 MiB")
        digest = hashlib.sha256()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
                temporary = Path(stream.name)
                for offset in range(0, size, DOWNLOAD_PART_BYTES):
                    token = secrets.token_hex(16)
                    count = min(DOWNLOAD_PART_BYTES, size - offset)
                    part = bytearray()
                    reply = self._copy_step(node, remote_path, timeout_sec, as_root, "pull_part", token,
                                            copy_offset=offset, copy_length=count, download=part)
                    checkpoint("ssh.pull_part")
                    if len(part) != count or not reply.startswith("SHA256:"):
                        raise ValueError("Download block checksum or length mismatch")
                    stream.write(part)
                    digest.update(part)
            if digest.hexdigest() != expected:
                raise ValueError("Download checksum mismatch: remote file may have changed")
            checkpoint("ssh.pull_commit")
            temporary.replace(destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return expected

    def bootstrap_ssh_key(self,*args,**kwargs):
        raise ValueError('Approve the SSH key and host fingerprint on Bastion before using structured_only')
