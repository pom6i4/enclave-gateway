"""Read-only readiness hints; release identity still requires fresh attestation."""
from __future__ import annotations
import datetime
import json
import time
from enclave_gateway.operations.context import OperationError,current,budget
from enclave_gateway.security.quoting import ps_quote


def require_running_worker(control,spec):
    path=spec.appliance_spool_dir.rstrip('\\/')+'\\worker_state.json'
    reader=getattr(control,'try_read_bytes',None)
    state=None
    if getattr(control,'supports_direct_spool_ipc',False) is True and callable(reader):
        raw=reader(path,truncate_after_read=False)
        if raw and len(raw)<=65536:
            try:
                state=json.loads(raw.decode('utf-8-sig'))
                stamp=state.get('last_heartbeat_utc','')
                age=time.time()-datetime.datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
                state={'running':state.get('status','running')=='running','age_sec':age}
            except (ValueError,TypeError,AttributeError):state=None
        if not raw:state={'running':False,'age_sec':-1}
    if state is None:
        script="$ErrorActionPreference='Stop';$p="+ps_quote(path)+";$out=@{running=$false;age_sec=-1};if([IO.File]::Exists($p)){$s=[IO.File]::ReadAllText($p)|ConvertFrom-Json;$out.running=($s.status -ne 'stopped' -and $s.status -ne 'stopping');$out.age_sec=([DateTime]::UtcNow-[IO.File]::GetLastWriteTimeUtc($p)).TotalSeconds};$out|ConvertTo-Json -Compress # EGW_WORKER_READINESS"
        result=control.exec_powershell(script,timeout_sec=budget(5,'vfs.preflight'))
        try:state=json.loads(result.stdout) if not result.exit_code else None
        except (ValueError,TypeError):state=None
    if not isinstance(state,dict) or state.get('running') is not True or type(state.get('age_sec')) not in (int,float) or not 0<=state['age_sec']<spec.heartbeat_max_age_sec:
        context=current()
        raise OperationError('session_pending_worker','vfs.preflight',tx_id=context.tx_id if context else '',node=context.node if context else '@bastion',
                             message='SESSION_PENDING_WORKER: no recent running heartbeat. Check RDP redirection and clocks; run the agents stage start_command inside Bastion. No request was published.')
