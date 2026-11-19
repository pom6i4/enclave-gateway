#!/usr/bin/env python3
"""Check a fresh installed stdio MCP server without a deployment connection."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time


INSPECT = r'''
import hashlib, importlib.metadata, json, pathlib, platform, sys, zipfile
from email.parser import BytesParser
import enclave_gateway
distribution = importlib.metadata.distribution('enclave-gateway')
package = pathlib.Path(enclave_gateway.__file__).resolve().parent
if 'site-packages' not in package.parts:
    raise ValueError('Expected an installed package outside the checkout')
if json.loads(distribution.read_text('direct_url.json') or '{}').get('dir_info', {}).get('editable'):
    raise ValueError('Editable installations are not accepted')
with zipfile.ZipFile(sys.argv[1]) as wheel:
    metadata, = [name for name in wheel.namelist() if name.endswith('.dist-info/METADATA')]
    version = BytesParser().parsebytes(wheel.read(metadata))['Version']
    expected = {name.removeprefix('enclave_gateway/'): hashlib.sha256(wheel.read(name)).hexdigest()
                for name in wheel.namelist() if name.startswith('enclave_gateway/') and not name.endswith('/')}
actual = {path.relative_to(package).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
          for path in package.rglob('*') if path.is_file() and '__pycache__' not in path.parts
          and path.suffix not in ('.pyc', '.pyo')}
if not expected or actual != expected:
    raise ValueError('Installed runtime differs from the supplied wheel')
if enclave_gateway.__version__ != version or distribution.version != version:
    raise ValueError('Wheel, module and installed metadata versions differ')
entries = {entry.name: entry.value for entry in distribution.entry_points if entry.group == 'console_scripts'}
if any(entries.get(name) != 'enclave_gateway.cli:main' for name in ('egw', 'enclave-gateway')):
    raise ValueError('Missing installed console entry points')
print(json.dumps({'version': version, 'runtime_files_verified': len(expected), 'runtime_mismatches': 0,
                  'installed_from_site_packages': True, 'editable': False,
                  'platform': {'system': platform.system(), 'machine': platform.machine(), 'python': platform.python_version()}}))
'''

# This is an accidental-I/O guard for the trusted test process, not an OS sandbox
# or a security boundary for hostile Python/native code.
SERVE = r'''
import json, pathlib, socket, subprocess, sys
def guard(event, args):
    if event.startswith('socket.') or event in ('subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.exec', 'os.spawn'):
        raise PermissionError('Local MCP fixture forbids network and subprocess I/O')
sys.addaudithook(guard)
for probe in (lambda: socket.socket(), lambda: socket.getaddrinfo('localhost', 9),
              lambda: subprocess.Popen([sys.executable, '-c', 'pass'])):
    try:
        probe()
    except PermissionError:
        pass
    else:
        raise RuntimeError('Local I/O guard was ineffective')
pathlib.Path(sys.argv[1]).write_text(json.dumps({'network_guard': 'python-audit', 'probes_passed': 3}))
sys.argv = ['egw', *sys.argv[2:]]
from importlib.metadata import distribution
entry, = [entry for entry in distribution('enclave-gateway').entry_points
          if entry.group == 'console_scripts' and entry.name == 'egw']
raise SystemExit(entry.load()())
'''


def validate_responses(raw, version):
    responses = {}
    for line in raw.splitlines():
        item = json.loads(line)
        if (item.get('jsonrpc') != '2.0' or type(item.get('id')) is not int
                or item['id'] in responses or 'error' in item or 'result' not in item):
            raise ValueError('Invalid or duplicate MCP response')
        responses[item['id']] = item['result']
    if set(responses) != {1, 2, 3, 4}:
        raise ValueError('Incomplete MCP smoke responses')
    initialized = responses[1]
    if (initialized.get('serverInfo') != {'name': 'enclave-gateway', 'version': version}
            or initialized.get('protocolVersion') != '2025-03-26' or responses[2] != {}):
        raise ValueError('MCP initialize/version/ping mismatch')
    tools = responses[3]['tools']
    names = [tool['name'] for tool in tools]
    if len(names) != len(set(names)) or not {'enclave_capabilities', 'node_transfer'} <= set(names):
        raise ValueError('Incomplete or duplicate MCP tool definitions')
    capability_result = responses[4]
    if capability_result.get('isError') is not False:
        raise ValueError('Local capabilities failed')
    capabilities = json.loads(capability_result['content'][0]['text'])
    if (capabilities['bastion_execution']['enabled'] is not False
            or capabilities['worker_verification']['applicable'] is not False):
        raise ValueError('Fixture unexpectedly enabled a remote worker')
    return {'serverInfo': initialized['serverInfo'], 'protocolVersion': initialized['protocolVersion'],
            'tools_list_count': len(tools), 'ping': 'passed', 'local_capabilities': 'passed'}


def exchange(python, args, requests, work, environment, output):
    """Sequence initialize before calls; bound reads on Windows as well as POSIX."""
    lines = queue.Queue(maxsize=16)
    raw = []
    deadline = time.monotonic()+45
    with (output/'mcp.stderr').open('xb') as errors:
        process = subprocess.Popen([str(python), '-I', '-B', '-c', SERVE, *args],
                                   cwd=work, env=environment, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors)
        def read():
            while True:
                line = process.stdout.readline(1024*1024+1)
                try:
                    lines.put_nowait(line)
                except queue.Full:
                    return
                if not line or len(line)>1024*1024:
                    return
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            for request in requests:
                process.stdin.write((json.dumps(request)+'\n').encode())
                process.stdin.flush()
                if 'id' not in request:
                    continue
                try:
                    line = lines.get(timeout=max(.001, deadline-time.monotonic()))
                except queue.Empty as error:
                    raise TimeoutError('Local MCP response deadline') from error
                if not line or len(line)>1024*1024:
                    raise ValueError('Missing or oversized local MCP response')
                raw.append(line)
                response = json.loads(line)
                if response.get('id') != request['id'] or 'error' in response:
                    raise ValueError('Unexpected local MCP response')
            process.stdin.close()
            if process.wait(timeout=max(.001, deadline-time.monotonic())):
                raise RuntimeError('Local MCP process failed')
            reader.join(timeout=2)
            if reader.is_alive():
                raise RuntimeError('Local MCP stdout did not close')
            while not lines.empty():
                if line := lines.get_nowait():
                    raw.append(line)
            return b''.join(raw)
        finally:
            if process.poll() is None:
                # Only this newly created child is eligible for failure cleanup.
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            reader.join(timeout=2)
            process.stdout.close()
            (output/'mcp.stdout').write_bytes(b''.join(raw))


def run(python: Path, wheel: Path, output: Path):
    python = python.absolute()  # Preserve a venv symlink's interpreter identity.
    wheel = wheel.resolve(strict=True)
    output = output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {'status': 'running', 'scope': 'installed-local-stdio-mcp',
              'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(),
              'real_configuration_used': False, 'existing_ide_sessions_touched': False}
    try:
        with tempfile.TemporaryDirectory(prefix='egw-mcp-') as temporary:
            work = Path(temporary).resolve()
            for name in ('home', 'tmp', 'state', 'runtime', 'xdg', 'appdata', 'localappdata'):
                (work / name).mkdir(mode=0o700)
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'SYSTEMDRIVE'}}
            environment.update(PATH=str(python.parent), HOME=str(work/'home'), USERPROFILE=str(work/'home'),
                               TMPDIR=str(work/'tmp'), TMP=str(work/'tmp'), TEMP=str(work/'tmp'),
                               APPDATA=str(work/'appdata'), LOCALAPPDATA=str(work/'localappdata'),
                               XDG_CONFIG_HOME=str(work/'xdg'), LANG='C.UTF-8')
            def command(label, args, data=None):
                completed = subprocess.run([str(python), '-I', '-B', *args], cwd=work, env=environment,
                                           input=data, capture_output=True, timeout=45)
                (output/(label+'.stdout')).write_bytes(completed.stdout)
                (output/(label+'.stderr')).write_bytes(completed.stderr)
                if completed.returncode:
                    raise RuntimeError(label+' failed; inspect private evidence')
                return completed.stdout
            inspected = json.loads(command('installed', ['-c', INSPECT, str(wheel)]))
            report.update(inspected)
            cli = command('version', ['-c', 'from enclave_gateway.cli import main; raise SystemExit(main())', '--version']).decode().strip()
            if cli != 'enclave-gateway '+inspected['version']:
                raise ValueError('Installed CLI version mismatch')
            config = work/'config.json'
            config.write_text(json.dumps({
                'appliance': {'name': 'local-mcp-check', 'hypervisor': 'direct', 'runtime_dir': str(work/'runtime'),
                              'disk_path': str(work/'unused.qcow2'), 'efi_vars_path': str(work/'unused.fd'),
                              'snapshot_dir': str(work/'unused-states')},
                'provider': {'type': 'custom', 'installer_path': '', 'dst_key_path': ''},
                'security': {'mode': 'standard'}, 'bastion': {'enabled': False}, 'targets': {}, 'forwards': {}}))
            config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
            requests = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                    'protocolVersion': '2025-03-26', 'capabilities': {},
                    'clientInfo': {'name': 'local-package-check', 'version': '1'}}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'},
                {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/list'},
                {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                 'params': {'name': 'enclave_capabilities', 'arguments': {}}}]
            raw = exchange(python, [str(work/'guard.json'), '-c', str(config), '--state-dir',
                                   str(work/'state'), 'mcp', '--read-only'], requests, work, environment, output)
            report.update(validate_responses(raw, inspected['version']))
            guard = json.loads((work/'guard.json').read_text())
            if guard != {'network_guard': 'python-audit', 'probes_passed': 3}:
                raise ValueError('Missing I/O guard evidence')
            if hashlib.sha256(config.read_bytes()).hexdigest() != config_hash:
                raise ValueError('Fixture configuration changed')
            if any((work/name).exists() for name in ('unused.qcow2', 'unused.fd', 'unused-states')):
                raise ValueError('Fixture unexpectedly created VM state')
            report.update(guard, status='passed', cli_version=cli, shutdown='stdin EOF', test_process_exit_code=0)
    except BaseException as error:
        report.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', required=True, type=Path, help='Interpreter of the installed noneditable environment.')
    parser.add_argument('--wheel', required=True, type=Path, help='Exact wheel installed in that environment.')
    parser.add_argument('--output', required=True, type=Path, help='New private evidence directory.')
    args = parser.parse_args()
    print(json.dumps(run(args.python, args.wheel, args.output), indent=2))
