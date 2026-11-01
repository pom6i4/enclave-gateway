#!/usr/bin/env python3
"""Qualify two already provisioned Linux UIDs through the actual MCP router."""
from __future__ import annotations
import argparse
import json
import os
import shlex
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.security.isolation import PrincipalRouter
from enclave_gateway.security.policy import AccessPolicy
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.audit.flight_recorder import FlightRecorder


def run(configuration):
    if not sys.platform.startswith('linux') or os.geteuid()!=0:raise RuntimeError('Use the disposable Linux root broker with pre-provisioned accounts')
    value=json.loads(configuration.read_text());policy=AccessPolicy.load(Path(value['broker_policy']))
    vault=SecretVault(env_file=Path(value['broker_environment']));router=PrincipalRouter(value['isolation_map'],vault=vault,policy=policy)
    names=list(router.specs)
    if len(names)!=2:raise ValueError('Exactly two disposable principals are required')
    marker='isolated-broker-marker';os.environ['EGW_BROKER_ONLY']=marker
    engine=EnclaveEngine(EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'}}),vault=vault,recorder=FlightRecorder(configuration.parent/'broker-audit.jsonl'))
    server=McpJsonRpcServer(engine,policy=policy,principal=names[0],router=router)
    checks=[]
    def call(name,tool,args):
        response=server.handle_message({'jsonrpc':'2.0','id':len(checks)+1,'method':'tools/call','params':{'name':tool,'arguments':args}},principal=name)
        return response
    try:
        for name in names:
            own=value['fixtures'][name];other=value['fixtures'][next(n for n in names if n!=name)]
            script='#'+'x'*200000+'\nid -u; cat '+shlex.quote(own['canary'])
            response=call(name,'node_exec',{'node':'fixture','script':script})
            assert 'result' in response and not response['result'].get('isError'),response
            backend=router._backends[name];uid=int(backend.spec['identity'].removeprefix('uid:'))
            assert os.stat('/proc/'+str(backend.process.pid)).st_uid==uid!=0
            assert str(uid) in json.dumps(response) and own['marker'] in json.dumps(response)
            environment=Path('/proc/'+str(backend.process.pid)+'/environ').read_bytes()
            assert marker.encode() not in environment and ('EGW_PROFILE='+name).encode() in environment
            checks.append(name+':uid-ssh-large-stdin-and-environment')
            for path in (other['canary'],other['environment'],value['broker_environment']):
                script='if test -r '+shlex.quote(path)+"; then echo ISOLATION_BYPASS; exit 1; else echo ACL_DENIED; fi"
                response=call(name,'node_exec',{'node':'fixture','script':script})
                assert 'ACL_DENIED' in json.dumps(response) and 'ISOLATION_BYPASS' not in json.dumps(response),response
            checks.append(name+':cross-account-acl-denial')
            sync=own['sync']
            for direction,local in (('push',sync['source']),('pull',sync['received'])):
                response=call(name,'node_sync',{'direction':direction,'local_dir':local,'node':'fixture','remote_dir':sync['remote'],'exclude':['*.tmp']})
                assert 'result' in response and not response['result'].get('isError'),response
            import hashlib
            for relative,digest in sync['files'].items():assert hashlib.sha256((Path(sync['received'])/relative).read_bytes()).hexdigest()==digest
            assert not (Path(sync['received'])/'skip.tmp').exists()
            assert (Path(sync['received'])/'keep.txt').read_text()=='preserve-extra-file'
            response=call(name,'node_sync',{'direction':'push','local_dir':sync['source'],'node':'fixture','remote_dir':str(Path(other['canary']).parent)})
            assert 'error' in response,response
            response=call(name,'node_exec',{'node':'@appliance','script':'id'})
            assert 'error' in response,response
            checks.append(name+':scoped-sync-and-controller-denial')
        return {'status':'passed','scope':'disposable-linux-two-uid-router','checks':checks,'windows_attestation':'not_exercised','client_environment':'not_used'}
    finally:
        router.close();os.environ.pop('EGW_BROKER_ONLY',None)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--configuration',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps({'status':'running'})+'\n')
    try:report=run(a.configuration)
    except BaseException as error:
        a.output.write_text(json.dumps({'status':'failed','error_type':type(error).__name__})+'\n');raise
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
