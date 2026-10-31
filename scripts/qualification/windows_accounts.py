#!/usr/bin/env python3
"""Qualify pre-provisioned disposable Windows principals; never create accounts."""
from __future__ import annotations

import argparse
import json
import os
import sys
import subprocess
import hashlib
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))


def run(configuration: Path):
    if os.name != 'nt':
        raise RuntimeError('Cross-SID acceptance requires a disposable Windows guest')
    from enclave_gateway.config import EnclaveConfig
    from enclave_gateway.engine import EnclaveEngine
    from enclave_gateway.mcp_server.server import McpJsonRpcServer
    from enclave_gateway.security.isolation import PrincipalRouter
    from enclave_gateway.security.policy import AccessPolicy
    from enclave_gateway.security.secrets import SecretVault

    raw = json.loads(configuration.read_text(encoding='utf-8-sig'))
    policy = AccessPolicy.load(Path(raw['broker_policy']))
    vault = SecretVault(env_file=Path(raw['broker_environment']))
    router = PrincipalRouter(raw['isolation_map'], vault=vault, policy=policy)
    names = list(router.specs)
    if len(names) != 2:
        raise ValueError('Fixture requires exactly two disposable principal profiles')
    engine = EnclaveEngine(EnclaveConfig.from_dict({'appliance': {'hypervisor': 'direct'}, 'provider': {'type': 'custom'}}), vault=vault)
    server = McpJsonRpcServer(engine, policy=policy, principal=names[0], router=router)
    current={}
    def call(name, number, tool, arguments):
        current.update(principal=name,case=number,tool=tool)
        print(json.dumps({'fixture_progress':current}),file=sys.stderr,flush=True)
        started=time.monotonic()
        response=server.handle_message({'jsonrpc': '2.0', 'id': number, 'method': 'tools/call',
                                      'params': {'name': tool, 'arguments': arguments}}, principal=name)
        print(json.dumps({'fixture_completed':dict(current),'elapsed_sec':round(time.monotonic()-started,3)}),file=sys.stderr,flush=True)
        return response
    outcomes = []
    try:
        for name in names:
            response = call(name, 1, 'enclave_capabilities', {})
            assert 'result' in response and not response['result'].get('isError'), response
            backend = router._backends[name]
            assert backend.spec['identity'].startswith('sid:')
            own = raw['fixtures'][name]
            other = raw['fixtures'][next(item for item in names if item != name)]
            script = "#" + "x"*100000 + "\n" + "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value; Get-Content -LiteralPath '" + own['canary'].replace("'", "''") + "'"
            response = call(name, 2, 'node_exec', {'node': 'fixture', 'script': script})
            assert 'result' in response and not response['result'].get('isError'), response
            rendered = json.dumps(response)
            assert backend.spec['identity'][4:] in rendered and own['marker'] in rendered
            # Arbitrary target execution tests the actual OS ACL, independently
            # of the file-tool path grant.
            script = "try { [IO.File]::ReadAllText('" + other['canary'].replace("'", "''") + "') | Out-Null; throw 'ISOLATION_BYPASS' } catch [UnauthorizedAccessException] { 'ACL_DENIED' }"
            response = call(name, 3, 'node_exec', {'node': 'fixture', 'script': script})
            assert 'ACL_DENIED' in json.dumps(response) and 'ISOLATION_BYPASS' not in json.dumps(response), response
            for number,private_path in enumerate((str(Path(router.specs[next(item for item in names if item != name)]['config']).parent/'.env'),raw['broker_environment']),5):
                probe="try { [IO.File]::ReadAllText('"+private_path.replace("'","''")+"') | Out-Null; throw 'ISOLATION_BYPASS' } catch [UnauthorizedAccessException] { 'ACL_DENIED' }"
                response=call(name,number,'node_exec',{'node':'fixture','script':probe})
                assert 'ACL_DENIED' in json.dumps(response) and 'ISOLATION_BYPASS' not in json.dumps(response),response
            if 'sync' in own:
                fixture=own['sync']
                for number,direction,local in ((10,'push',fixture['source']),(11,'pull',fixture['received'])):
                    response=call(name,number,'node_sync',{'direction':direction,'local_dir':local,'node':'fixture','remote_dir':fixture['remote'],'exclude':['*.tmp']})
                    assert 'result' in response and not response['result'].get('isError'),response
                for relative,digest in fixture['files'].items():
                    assert hashlib.sha256((Path(fixture['received'])/relative).read_bytes()).hexdigest()==digest
                assert (Path(fixture['received'])/'keep.txt').read_text()=='preserve-extra-file'
                assert not (Path(fixture['received'])/'skip.tmp').exists()
                denied_sync=call(name,12,'node_sync',{'direction':'push','local_dir':fixture['source'],'node':'fixture','remote_dir':str(Path(other['canary']).parent)})
                assert 'error' in denied_sync,denied_sync
            spec=backend.spec
            request={'command':[spec['python'],'-c',"print('forbidden-launch')"], 'username':spec['username'],
                     'domain':spec.get('domain','.'),'password':vault.get(spec['password_env']),'expected_sid':'S-1-5-18'}
            rejected=subprocess.run([spec['runtime_helper'],'run-as'],input=json.dumps(request)+'\n',text=True,encoding='utf-8',capture_output=True,timeout=30)
            assert rejected.returncode and 'forbidden-launch' not in rejected.stdout
            denied = call(name, 4, 'node_exec', {'node': '@appliance', 'script': "Write-Output 'forbidden'"})
            assert 'error' in denied, denied
            assert str(router._backends[name].process.pid) not in outcomes
            outcomes.append(str(router._backends[name].process.pid))
        assert len(set(outcomes)) == 2
        return {'status': 'passed', 'platform': 'Windows', 'cross_sid_backends': 2,
                'private_environment_and_state': 'configured', 'own_target_sid': 'passed',
                'cross_account_acl_denial': 'passed', 'private_environment_acl_denial':'passed',
                'wrong_sid_launch_denial':'passed','large_ssh_stdin':'passed', 'controller_execution_denial': 'passed',
                'scoped_windows_sync':'passed' if all('sync' in raw['fixtures'][name] for name in names) else 'not_configured',
                'customer_environment': 'not_used'}
    finally:
        router.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'status':'running','scope':'disposable-windows-principals'})+'\n',encoding='utf-8')
    failure=None
    try:
        result=run(args.configuration)
    except Exception as error:
        failure=error
        result={'status':'failed','scope':'disposable-windows-principals','error_type':type(error).__name__}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    if failure is not None: raise failure
