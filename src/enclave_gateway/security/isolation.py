"""One persistent backend process and OS identity per authenticated principal."""
from __future__ import annotations
import json
import os
if os.name != "nt":
    import pwd
import queue
import subprocess
import sys
import threading
from pathlib import Path
from enclave_gateway.operations.context import OperationError


def process_identity():
    if os.name!='nt': return 'uid:'+str(os.geteuid())
    import ctypes
    from ctypes import wintypes
    advapi=ctypes.WinDLL('advapi32',use_last_error=True); kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    token=wintypes.HANDLE(); size=wintypes.DWORD()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)): raise ctypes.WinError(ctypes.get_last_error())
    try:
        advapi.GetTokenInformation(token,1,None,0,ctypes.byref(size)); data=ctypes.create_string_buffer(size.value)
        if not advapi.GetTokenInformation(token,1,data,size,ctypes.byref(size)): raise ctypes.WinError(ctypes.get_last_error())
        text=wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(ctypes.cast(data,ctypes.POINTER(ctypes.c_void_p))[0],ctypes.byref(text)): raise ctypes.WinError(ctypes.get_last_error())
        try: return 'sid:'+text.value
        finally: kernel.LocalFree(ctypes.cast(text,ctypes.c_void_p))
    finally: kernel.CloseHandle(token)


def process_privileged():
    if os.name!='nt': return os.geteuid()==0
    import ctypes
    from ctypes import wintypes
    api=ctypes.WinDLL('advapi32',use_last_error=True); kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    api.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    api.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    token=wintypes.HANDLE(); size=wintypes.DWORD(); elevated=wintypes.DWORD()
    if not api.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)): raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.GetTokenInformation(token,20,ctypes.byref(elevated),ctypes.sizeof(elevated),ctypes.byref(size)): raise ctypes.WinError(ctypes.get_last_error())
        return bool(elevated.value)
    finally: kernel.CloseHandle(token)


class Backend:
    def __init__(self, principal, spec, *, vault=None, allow_same_user_for_tests=False):
        self.principal=principal; self.spec=spec
        expected=spec['identity']
        if expected==process_identity() and not allow_same_user_for_tests:
            raise ValueError('An isolated backend must use another OS account')
        configuration=Path(spec['config']).resolve(); policy=Path(spec['policy']).resolve()
        command=[spec.get('python',sys.executable),'-m','enclave_gateway.cli','--config',str(configuration),'mcp',
                 '--policy',str(policy),'--principal',principal,'--worker-identity-handshake',
                 '--worker-state-dir',str(Path(spec.get('state_dir',configuration.parent/'state')).resolve())]
        environment={key:value for key,value in os.environ.items() if key.upper() in ('PATH','SYSTEMROOT','SYSTEMDRIVE','WINDIR','COMSPEC','PATHEXT','PROGRAMFILES','PROGRAMFILES(X86)')}
        environment.update(spec.get('environment',{}))
        options={}
        request=None
        if os.name!='nt':
            if not expected.startswith('uid:'): raise ValueError('POSIX backend requires a UID')
            uid=int(expected[4:]); account=pwd.getpwuid(uid)
            environment.update(HOME=account.pw_dir,USER=account.pw_name,LOGNAME=account.pw_name)
            if uid!=os.geteuid(): options.update(user=uid,group=account.pw_gid,extra_groups=[])
        else:
            if not expected.startswith('sid:'): raise ValueError('Windows backend requires an immutable SID')
            from enclave_gateway.security.native import verified_runtime
            if not spec.get('runtime_sha256'): raise ValueError('Pin the broker native runtime before credential delegation')
            helper=verified_runtime(spec['runtime_helper'],spec.get('trusted_signers',()),True,expected_sha256=spec['runtime_sha256'])
            if vault is None: raise ValueError('Backend logon requires the broker vault')
            request={'command':command,'expected_sid':expected[4:],'username':spec['username'],'domain':spec.get('domain','.'),
                     'password':vault.get(spec['password_env']),'environment':dict(spec.get('environment',{}))}
            command=[helper,'run-as']
        self.process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                                      text=True,encoding="utf-8",bufsize=1,env=environment,start_new_session=(os.name!='nt'),**options)
        self._write_lock=threading.Lock(); self._pending_lock=threading.Lock(); self._pending={}; self._sequence=0
        self._ready=queue.Queue(1)
        self._handshake_sent=False
        if request:
            self.process.stdin.write(json.dumps(request)+'\n'); self.process.stdin.flush()
        self._reader=threading.Thread(target=self._read,daemon=True); self._reader.start()
        try:
            ready=self._ready.get(timeout=15)
            if (not isinstance(ready,dict) or ready.get('egw_worker_identity')!=expected
                    or ready.get('principal')!=principal or ready.get('config')!=str(configuration)
                    or (ready.get('privileged',True) and not allow_same_user_for_tests)):
                raise PermissionError('Backend identity/configuration handshake mismatch')
        except BaseException:
            self.close(); raise

    def _read(self):
        try:
            line=self.process.stdout.readline(8*1024*1024+1)
            self._ready.put(json.loads(line)); self._handshake_sent=True
            while True:
                line=self.process.stdout.readline(8*1024*1024+1)
                if not line: break
                if len(line)>8*1024*1024: raise ValueError('Backend response too large')
                response=json.loads(line)
                with self._pending_lock: destination=self._pending.get(response.get('id'))
                if destination: destination.put(response)
        except Exception:
            pass
        finally:
            if not self._handshake_sent:
                try:self._ready.put_nowait(None)
                except queue.Full:pass
            with self._pending_lock:
                for key,destination in self._pending.items():
                    if not isinstance(key,tuple): destination.put(None)

    def handle(self,message,*,cancel_requested=lambda:False):
        request=dict(message); original_id=request.get('id'); notification='id' not in request
        with self._pending_lock:
            if sum(not isinstance(key,tuple) for key in self._pending)>=16: raise OperationError('backend_busy','isolation')
            if not notification:
                if ('client',original_id) in self._pending: raise OperationError('duplicate_request_id','isolation')
                self._sequence+=1; backend_id=self._sequence
                destination=queue.Queue(); self._pending[backend_id]=destination
                request['id']=backend_id
                # Map cancellation to backend ids while maintaining principal ownership.
                self._pending[('client',original_id)]=backend_id
            elif request.get('method')=='notifications/cancelled':
                target=request.get('params',{}).get('requestId')
                if isinstance(target,(dict,list,bool)): return None
                request['params']=dict(request.get('params',{}))
                request['params']['requestId']=self._pending.get(('client',request['params'].get('requestId')),-1)
        try:
            with self._write_lock:
                self.process.stdin.write(json.dumps(request)+'\n'); self.process.stdin.flush()
            if notification: return None
            if cancel_requested():
                with self._write_lock:
                    self.process.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':backend_id}})+'\n');self.process.stdin.flush()
            try: response=destination.get(timeout=1000)
            except queue.Empty: raise OperationError('backend_timeout','isolation',indeterminate=True)
            if response is None: raise OperationError('backend_unavailable','isolation',indeterminate=True)
            response['id']=original_id; return response
        finally:
            if not notification:
                with self._pending_lock:
                    self._pending.pop(backend_id,None); self._pending.pop(('client',original_id),None)

    def close(self):
        if getattr(self,'process',None):
            if self.process.poll() is None:
                if os.name!='nt':
                    import signal
                    self.process.terminate()
                    try: self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try: os.killpg(self.process.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                else: self.process.kill()
            self.process.wait(timeout=5)
            for stream in (self.process.stdin,self.process.stdout):
                if stream: stream.close()


class PrincipalRouter:
    def __init__(self,path,*,vault=None,policy=None):
        raw=json.loads(Path(path).read_text(encoding='utf-8-sig'))
        if set(raw)!={'principals'} or not raw['principals']: raise ValueError('Invalid isolation map')
        self.specs=raw['principals']; self.vault=vault; self._backends={}; self._lock=threading.Lock()
        identities=[spec['identity'] for spec in self.specs.values()]
        if len(set(identities))!=len(identities) or process_identity() in identities:
            raise ValueError('Broker and principal workers require distinct OS identities')
        state_dirs=[str(Path(spec.get('state_dir',Path(spec['config']).resolve().parent/'state')).resolve()) for spec in self.specs.values()]
        if len(set(state_dirs))!=len(state_dirs): raise ValueError('Workers require separate private state directories')
        configs=[str(Path(spec['config']).resolve()) for spec in self.specs.values()]
        if len(set(configs))!=len(configs): raise ValueError('Workers require separate configuration/credentials/spool profiles')
        accounts=[]; spools=[]; machines=[]; disks=[]; targets=[]
        from enclave_gateway.security.policy import AccessPolicy
        from dataclasses import asdict
        def permissions(grant):
            return json.dumps({key:value for key,value in asdict(grant).items() if key not in ('name','token_env')},sort_keys=True)
        from enclave_gateway.config import EnclaveConfig
        for principal,spec in self.specs.items():
            backend_policy=AccessPolicy.load(Path(spec['policy']))
            grant=backend_policy.grant(principal)
            if grant.allow_root: raise ValueError('Untrusted principal profiles must not grant sudo/root execution')
            controller_nodes={'*','@appliance','appliance','@bastion','bastion'}
            node_tools=('node_exec','node_db_query','node_read_file','node_transfer','node_sync','node_patch_file','node_http_request')
            if any(node in controller_nodes for node in grant.nodes):
                for tool in node_tools:
                    if grant.permits_tool(tool):
                        nodes=grant.tool_nodes.get(tool)
                        if nodes is None or any(node in ('*','@appliance','appliance','@bastion','bastion') for node in nodes):
                            raise ValueError('Untrusted workers require explicit target-only command grants')
            if any(node in grant.write_roots for node in ('*','@appliance','appliance','@bastion','bastion')) or grant.unrestricted_paths:
                raise ValueError('Untrusted roles must not write controller files or have unrestricted paths')
            if set(backend_policy.grants)!={principal} or policy is None or permissions(backend_policy.grant(principal))!=permissions(policy.grant(principal)):
                raise ValueError('Backend policy must match the broker grant for exactly one principal')
            data_root=Path(spec.get('state_dir',Path(spec['config']).resolve().parent/'state')).resolve()/'data'
            for value in (*grant.local_read_roots,*grant.local_write_roots):
                if not Path(value).expanduser().resolve().is_relative_to(data_root):
                    raise ValueError('Untrusted file endpoints must stay inside the private profile data directory')
            config=EnclaveConfig.load(spec['config']); security=config.security
            if any(target.user.lower() in ('root','administrator',r'nt authority\system') for target in config.targets.values()):
                raise ValueError('Untrusted profiles require dedicated non-administrative SSH target accounts')
            if not (security.require_signed_agents and security.require_signed_helpers and security.trusted_signers and security.worker_account and security.worker_sha256 and security.runtime_sha256 and security.enforce_worker_attestation and security.require_process_isolation and security.owned_ssh_commands):
                raise ValueError('Isolated profiles require pinned worker account, attestation, process isolation and owned SSH commands')
            accounts.append(security.worker_account); spools.append(config.bastion.appliance_spool_dir)
            if config.appliance.hypervisor!='direct':
                machines.append((config.appliance.runtime_dir,config.appliance.name))
                disks.append(str(config.appliance.resolved_disk_path))
            targets.extend((target.host,target.port,target.user) for target in config.targets.values())
        if len(set(accounts))!=len(accounts) or len(set(spools))!=len(spools):
            raise ValueError('Principal profiles must not share a remote OS account or spool')
        if len(set(machines))!=len(machines) or len(set(disks))!=len(disks) or len(set(targets))!=len(targets):
            raise ValueError('Isolated profiles must not share writable VMs or SSH target accounts')

    def handle(self,principal,message,*,cancel_requested=lambda:False):
        with self._lock:
            if principal not in self.specs: raise OperationError('access_denied','isolation',message='No isolated backend for this principal')
            if principal not in self._backends:
                try: self._backends[principal]=Backend(principal,self.specs[principal],vault=self.vault)
                except (OSError,ValueError,PermissionError,KeyError,subprocess.SubprocessError,queue.Empty) as exc:
                    raise OperationError('backend_start_failed','isolation',message='Isolated worker could not start; verify account privileges, runtime and profile permissions') from exc
            backend=self._backends[principal]
        try: return backend.handle(message,cancel_requested=cancel_requested)
        except (BrokenPipeError,OSError) as exc: raise OperationError('backend_unavailable','isolation',indeterminate=True) from exc

    def close(self):
        for backend in self._backends.values(): backend.close()
