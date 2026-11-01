#!/usr/bin/env python3
"""Use a tiny owned tmpfs to verify real ENOSPC and journal corruption handling."""
from __future__ import annotations
import argparse
import errno
import json
import os
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.agents.rooted_fs import RootedFS,MAX_CHUNK
from enclave_gateway.control.qga_client import DirectHostControlChannel
from enclave_gateway.operations.journal import TransactionJournal
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.security.secrets import SecretVault


class ObservedShell(DirectHostControlChannel):
    def __init__(self):super().__init__();self.dispatches=0
    def exec_powershell(self,*args,**kwargs):self.dispatches+=1;return super().exec_powershell(*args,**kwargs)


def fill(path):
    try:
        with path.open('wb') as stream:
            while True:stream.write(b'x'*65536);stream.flush();os.fsync(stream.fileno())
    except OSError as error:
        if error.errno!=errno.ENOSPC:raise


def run(workspace):
    if not sys.platform.startswith('linux') or os.geteuid()!=0:raise RuntimeError('Run only in the disposable Linux root fixture')
    if workspace.exists():raise FileExistsError('Use a new disposable workspace')
    workspace.mkdir(parents=True,mode=0o700);mount=workspace/'full';mount.mkdir(mode=0o700)
    report={'status':'running','scope':'disposable-linux-real-storage-faults','checks':[]};mounted=False
    def engine(journal,control):return EnclaveEngine(EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'}}),
                    journal=journal,control_override=control,recorder=FlightRecorder(workspace/'audit.jsonl'),vault=SecretVault(env_file=workspace/'absent.env'))
    try:
        subprocess.run(['mount','-t','tmpfs','-o','size=1m,mode=700','egw-storage-fixture',str(mount)],check=True);mounted=True
        (mount/'kept').write_bytes(b'previous-destination')
        with RootedFS(str(mount)) as fs:
            offset=0;failed=False
            try:
                for _ in range(16):fs.write('stage',offset,b'x'*MAX_CHUNK);offset+=MAX_CHUNK
            except OSError as error:failed=error.errno==errno.ENOSPC
            assert failed and (mount/'kept').read_bytes()==b'previous-destination'
            fs.remove('stage')
        report['checks'].append('real-enospc-keeps-destination')
        journal=TransactionJournal(mount/'journal.sqlite3')
        with journal.connect():pass
        fill(mount/'filler');control=ObservedShell();gateway=engine(journal,control)
        failed=False
        try:gateway.exec_node('@appliance','printf forbidden',tx_id='full_before_dispatch',timeout_sec=5)
        except Exception:failed=True
        assert failed and control.dispatches==0
        (mount/'filler').unlink();assert journal.get('full_before_dispatch','local') is None
        report['checks'].append('full-journal-fails-before-dispatch')
        # Fill storage from inside a real executed command, after reservation.
        payload="import os,errno; p="+repr(str(mount/'filler2'))+"; f=open(p,'wb');\ntry:\n while True:f.write(b'x'*65536);f.flush();os.fsync(f.fileno())\nexcept OSError as e:\n assert e.errno==errno.ENOSPC\nf.close()\n"
        import shlex,base64
        script="printf x >> "+shlex.quote(str(workspace/'effect'))+"\nprintf %s "+shlex.quote(base64.b64encode(payload.encode()).decode())+" | base64 -d | python3\nprintf observed"
        failed=False
        try:gateway.exec_node('@appliance',script,tx_id='full_after_dispatch',timeout_sec=1)
        except Exception:failed=True
        assert failed and control.dispatches==1 and (workspace/'effect').read_text()=='x'
        (mount/'filler2').unlink();journal.reconcile_expired('local')
        try:gateway.exec_node('@appliance',script,tx_id='full_after_dispatch',timeout_sec=5)
        except Exception:pass
        else:raise AssertionError('Uncertain storage failure was replayed')
        assert control.dispatches==1 and (workspace/'effect').read_text()=='x'
        report['checks'].append('full-result-journal-never-replays-effect')
        bad=workspace/'corrupt.sqlite3';bad.write_bytes(b'not-a-database'*4096);bad_control=ObservedShell()
        failed=False
        try:engine(TransactionJournal(bad),bad_control).exec_node('@appliance','printf forbidden',tx_id='corrupt',timeout_sec=5)
        except Exception:failed=True
        assert failed and bad_control.dispatches==0
        report['checks'].append('corrupt-journal-fails-before-dispatch');report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        if mounted:subprocess.run(['umount',str(mount)],check=True)
        (workspace/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--workspace',required=True,type=Path);run(p.parse_args().workspace.resolve())
