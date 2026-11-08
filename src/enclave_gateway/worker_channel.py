"""Read-only readiness hints; release identity still requires fresh attestation."""
from __future__ import annotations
import datetime
import json
import time
from enclave_gateway.operations.context import OperationError,current,budget,read_only_preflight
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.control.qga_client import QgaCommandError


def stream_worker_state(control, spec):
    """Newest fresh same-instance snapshot, including stopped snapshots.

    None means no descriptor; {} means a descriptor without usable telemetry.
    A publishing/locked slot never authorizes falling back to an older instance.
    This is a liveness hint, not a substitute for attestation.
    """
    session=getattr(type(control),'read_session',None)
    if callable(session):
        with control.read_session() as reader:return _stream_state_from_reader(reader,spec)
    return _stream_state_from_reader(getattr(control,'try_read_bytes',None),spec)


def _stream_state_from_reader(reader,spec):
    from enclave_gateway.transports.stream_frames import descriptor
    if not callable(reader):return None
    root=spec.appliance_spool_dir.rstrip('\\/')+'\\'
    try:
        raw=reader(root+'ipc_descriptor.json',truncate_after_read=False)
        if not raw or len(raw)>4096:return None
        info=descriptor(raw)
    except (ValueError,UnicodeError):return None
    except QgaCommandError as error:
        if error.command=='guest-file-open':return None
        raise
    candidates=[]
    for slot in ('a','b'):
        try:
            raw=reader(root+'worker_pulse_'+info['instance']+'_'+slot+'.json',truncate_after_read=False)
            if not raw or len(raw)>65536:continue
            value=json.loads(raw.decode('utf-8-sig'))
            if (not isinstance(value,dict) or value.get('instance_id')!=info['instance']
                    or value.get('worker_sha256')!=info['worker_sha256']
                    or value.get('spool_protocol')!='stream'
                    or value.get('status') not in ('running','stopping','stopped')):continue
            stamp=datetime.datetime.fromisoformat(value['last_heartbeat_utc'].replace('Z','+00:00')).timestamp()
            if 0<=time.time()-stamp<spec.heartbeat_max_age_sec:candidates.append((stamp,value))
        except (ValueError,TypeError,KeyError,AttributeError,UnicodeError,RecursionError):continue
        except QgaCommandError as error:
            if error.command!='guest-file-open':raise
    return max(candidates,key=lambda item:(item[0],item[1].get('status')!='running'))[1] if candidates else {}


def _structured_worker_state(control,path,spec):
    reader=getattr(type(control),'read_file_snapshot',None)
    try:
        if callable(reader):
            raw,stamp=reader(control,path)
        else:
            # QGA guest-file commands expose bytes but no file timestamps.
            # Hold the same file open when reading the state and its timestamp.
            script="$ErrorActionPreference='Stop';$p="+ps_quote(path)+"""
if([IO.File]::Exists($p)){
    $file=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try{
        if($file.Length -le 65536){
            $reader=[IO.StreamReader]::new($file)
            try{
                $state=$reader.ReadToEnd()
                $stamp=[DateTimeOffset]::new([IO.File]::GetLastWriteTimeUtc($p)).ToUnixTimeMilliseconds()
                @{state=$state;stamp_ms=$stamp}|ConvertTo-Json -Compress
            }finally{$reader.Dispose()}
        }
    }finally{$file.Dispose()}
} # EGW_STRUCTURED_READINESS
"""
            with read_only_preflight():
                try:
                    result = control.exec_powershell(script, timeout_sec=budget(5, 'vfs.preflight'))
                except TimeoutError:
                    # The snapshot cannot dispatch a worker operation. A slow
                    # guest can get one fresh read within the caller's deadline.
                    result = control.exec_powershell(script, timeout_sec=budget(5, 'vfs.preflight'))
            if result.exit_code or not result.stdout:return {}
            snapshot=json.loads(result.stdout)
            raw=snapshot['state'].encode('utf-8')
            stamp=snapshot['stamp_ms']/1000
        if not raw or len(raw)>65536:return {}
        value=json.loads(raw.decode('utf-8-sig'))
        state={'running':value.get('status')=='running','age_sec':time.time()-stamp,
                'spool_protocol':value.get('spool_protocol','files'),
                '_heartbeat_expires_unix':stamp+spec.heartbeat_max_age_sec,
                'execution_profile':value.get('execution_profile'),
                'structured_backend':value.get('structured_backend', 'spawn'),
                'probe_direct_reply':value.get('probe_direct_reply') is True,
                'worker_state':value}
        if state['structured_backend'] == 'operator' and state['spool_protocol'] == 'stream':
            from enclave_gateway.transports.stream_frames import BLOCK, REVISION, descriptor
            state['_stream_descriptor'] = descriptor(json.dumps({
                'revision': REVISION, 'block_bytes': BLOCK, 'instance': value.get('instance_id'),
                'worker_sha256': value.get('worker_sha256'),
            }).encode())
        return state
    except (ValueError,TypeError,KeyError,AttributeError):
        return {}


def require_running_worker(control,spec):
    path=spec.appliance_spool_dir.rstrip('\\/')+'\\worker_state.json'
    reader=getattr(control,'try_read_bytes',None)
    state=_structured_worker_state(control,path,spec) if spec.execution_profile=='structured_only' else None
    snapshot=stream_worker_state(control,spec) if spec.spool_protocol=='stream' and spec.execution_profile!='structured_only' else None
    if snapshot is not None:
        age=-1;stamp=None
        if snapshot:
            stamp=datetime.datetime.fromisoformat(snapshot['last_heartbeat_utc'].replace('Z','+00:00')).timestamp()
            age=time.time()-stamp
        state={'running':snapshot.get('status')=='running','age_sec':age,'spool_protocol':'stream',
               '_heartbeat_expires_unix':stamp+spec.heartbeat_max_age_sec if stamp is not None else None}
        if snapshot:
            from enclave_gateway.transports.stream_frames import BLOCK,REVISION
            state['_stream_descriptor']={'revision':REVISION,'block_bytes':BLOCK,'instance':snapshot['instance_id'],'worker_sha256':snapshot['worker_sha256']}
    if state is None and (getattr(control,'supports_direct_spool_ipc',False) is True or spec.spool_protocol=='stream') and callable(reader):
        deadline=time.monotonic()+budget(.5,'vfs.preflight')
        while True:
            try:raw=reader(path,truncate_after_read=False);break
            except QgaCommandError as error:
                if error.command!='guest-file-open':raise
                if time.monotonic()>=deadline:
                    raise OperationError('worker_state_unavailable','vfs.preflight',node='@bastion',message='Cannot read worker heartbeat; check Appliance spool permissions and busy file handles. No request was published.') from error
                time.sleep(.005)
        if raw and len(raw)<=65536:
            try:
                state=json.loads(raw.decode('utf-8-sig'))
                stamp=state.get('last_heartbeat_utc','')
                stamp=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
                age=time.time()-stamp
                state={'running':state.get('status','running')=='running','age_sec':age,'spool_protocol':state.get('spool_protocol','files'),
                       '_heartbeat_expires_unix':stamp+spec.heartbeat_max_age_sec}
            except (ValueError,TypeError,AttributeError):state=None
        if not raw:state={'running':False,'age_sec':-1}
    if state is None:
        script="$ErrorActionPreference='Stop';$p="+ps_quote(path)+";$out=@{running=$false;age_sec=-1;spool_protocol='files'};if([IO.File]::Exists($p)){$s=[IO.File]::ReadAllText($p)|ConvertFrom-Json;$out.spool_protocol=if($s.spool_protocol){$s.spool_protocol}else{'files'};$out.running=($s.status -ne 'stopped' -and $s.status -ne 'stopping');$out.age_sec=([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($p)).TotalSeconds};$out|ConvertTo-Json -Compress # EGW_WORKER_READINESS"
        result=control.exec_powershell(script,timeout_sec=budget(5,'vfs.preflight'))
        try:state=json.loads(result.stdout) if not result.exit_code else None
        except (ValueError,TypeError):state=None
    if not isinstance(state,dict) or state.get('running') is not True or type(state.get('age_sec')) not in (int,float) or not 0<=state['age_sec']<spec.heartbeat_max_age_sec:
        context=current()
        raise OperationError('session_pending_worker','vfs.preflight',tx_id=context.tx_id if context else '',node=context.node if context else '@bastion',
                             message='SESSION_PENDING_WORKER: no recent running heartbeat. Check RDP redirection and clocks; run the agents stage start_command inside Bastion. No request was published.')

    if state.get('spool_protocol','files') != spec.spool_protocol:
        context=current()
        raise OperationError('worker_protocol_mismatch','vfs.preflight',tx_id=context.tx_id if context else '',node='@bastion',
                             message='Worker spool protocol differs from bastion.spool_protocol. Stop the worker, stage agents and start the printed command using the same configuration. No request was published.')

    if spec.execution_profile=='structured_only':
        if state.get('execution_profile')!='structured_only':
            raise OperationError('worker_profile_mismatch','vfs.preflight',node='@bastion',message='Start the approved foreground structured worker; legacy workers cannot receive structured requests.')

        if state.get('structured_backend', 'spawn') != spec.structured_backend:
            raise OperationError('worker_profile_mismatch','vfs.preflight',node='@bastion',message='The running worker uses a different structured OpenSSH backend.')

    return state
