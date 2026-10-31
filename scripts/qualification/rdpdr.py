#!/usr/bin/env python3
"""Qualify an already redirected disposable Windows spool; never open an RDP login."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import secrets
import sys
from pathlib import Path, PureWindowsPath
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from worker_loopback import FileChannel
from enclave_gateway.config import BastionSpec
from enclave_gateway.security.attestation import verify
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport


def run(configuration: Path, phase: str, output: Path):
    options = json.loads(configuration.read_text(encoding='utf-8-sig'))
    remote = PureWindowsPath(options['remote_dir'])
    if not remote.is_absolute() or remote.drive.startswith('\\\\'):
        raise ValueError('Use a dedicated absolute guest directory')
    transport = RdpVfsTransport(FileChannel(Path(options['spool']), ''), BastionSpec(
        appliance_spool_dir=options['spool'], bastion_spool_dir=options['remote_spool']))
    def guard():
        nonce = secrets.token_hex(32)
        evidence = verify(transport.attest(nonce), nonce, expected_sha256=options['worker_sha256'],
                          expected_runtime_sha256=options['runtime_sha256'], trusted_signers=[options['signer']],
                          expected_account=options['sid'], require_process_isolation=True)
        assert evidence.get('spool_kind') == 'redirected' and evidence.get('session_id', 0) > 0, evidence
        return evidence
    transport.attestation_guard = guard
    evidence = guard()
    marker = str(remote / 'executions.txt')
    script = '[IO.File]::AppendAllText(' + ps_quote(marker) + ", 'x'); Write-Output 'rdp-once'"
    envelope = {'tx_id': options['tx_id'], 'op': 'exec', 'timeout_ms': 30000,
                'payload_b64': base64.b64encode(script.encode()).decode()}
    result = {'status': 'passed', 'scope': 'disposable-redirected-windows-spool', 'phase': phase,
              'session_id': evidence['session_id'], 'worker_instance': evidence['instance_id'],
              'worker_sha256': evidence['loaded_sha256'], 'signature_attestation': 'passed'}
    if phase == 'before':
        response = transport._dispatch_envelope(envelope, timeout_sec=35)
        assert response.exit_code == 0 and response.stdout == 'rdp-once', response
        with TemporaryDirectory() as temporary:
            folder = Path(temporary)
            data = secrets.token_bytes(4194305)
            source = folder / 'source'
            source.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            target = str(remote / "файл ' тест.bin")
            assert transport.push_file(source, target) == expected
            assert transport.pull_file(target, folder / 'received') == expected
            assert (folder / 'received').read_bytes() == data
        result['roundtrip_bytes'] = len(data)
        result['roundtrip_sha256'] = expected
    else:
        before = json.loads((output.parent / 'before.json').read_text(encoding='utf-8'))
        assert before.get('status')=='passed' and before.get('phase')=='before', 'First phase must have passed'
        assert evidence['loaded_sha256']==before['worker_sha256'], 'Keep the same approved release across phases'
        assert evidence['instance_id'] != before['worker_instance'], 'Restart the disposable worker between phases'
        response = transport._dispatch_envelope(envelope, timeout_sec=35)
        assert response.exit_code == 125, response
        response = transport.exec_bastion('[IO.File]::ReadAllText(' + ps_quote(marker) + ')', timeout_sec=30)
        assert response.stdout == 'x', response
        result['restart_no_replay'] = 'passed'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', required=True, type=Path)
    parser.add_argument('--phase', required=True, choices=['before', 'after'])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.phase == 'before' and args.output.name != 'before.json':
        parser.error('Store the first phase as before.json beside the later phase report')
    if args.phase=='after' and args.output.name=='before.json':
        parser.error('Preserve before.json for comparison')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'status':'running','phase':args.phase})+'\n',encoding='utf-8')
    try:
        print(json.dumps(run(args.configuration,args.phase,args.output),indent=2))
    except Exception as error:
        args.output.write_text(json.dumps({'status':'failed','phase':args.phase,'error_type':type(error).__name__})+'\n',encoding='utf-8')
        raise
