"""Explicit local tool identities and behavioral probes for qualification."""
from __future__ import annotations
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('reproducible_build',ROOT/'scripts/release/reproducible_build.py')
release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)


def socket_probe():
    with socket.socket() as s:s.bind(('127.0.0.1',0));s.listen(1)
    if hasattr(socket,'AF_UNIX') and os.name!='nt':
        with tempfile.TemporaryDirectory(prefix='egw-probe-',dir='/tmp') as folder,socket.socket(socket.AF_UNIX) as s:s.bind(str(Path(folder)/'s'))


def askpass_probe(dotnet,helper,env):
    fixture='fixture \' " ` $ ; & тест'
    value={**env,'EGW_ASKPASS_B64':base64.b64encode(fixture.encode()).decode()}
    p=subprocess.run([dotnet,str(helper),'ignored prompt'],env=value,capture_output=True,timeout=10)
    if p.returncode or p.stdout.decode('utf-8').strip()!=fixture or p.stderr:raise ValueError('Artifact is not the dedicated askpass helper')
    p=subprocess.run([dotnet,str(helper)],env={**env,'EGW_ASKPASS_B64':'!invalid'},capture_output=True,timeout=10)
    if p.returncode!=2 or p.stdout or p.stderr:raise ValueError('Askpass invalid-input contract failed')


def preflight(manifest,output):
    output=output.resolve()
    if output.exists():raise FileExistsError('Use a new preflight directory')
    output.mkdir(parents=True,mode=0o700);report={'status':'running','checks':[]}
    env=release.tool_environment(manifest)
    try:
        socket_probe();report['checks'].append('local-tcp-and-unix-sockets')
        python=release.checked_tool(manifest['python'],['-c','import platform;print(platform.python_version())'],env)
        dotnet=release.checked_tool(manifest['dotnet'],['--version'],env)
        powershell=release.checked_tool(manifest['powershell'],['-NoProfile','-NonInteractive','-Command','$PSVersionTable.PSVersion.ToString()'],env)
        build=json.loads(subprocess.check_output([python,'-c',"import importlib.metadata,json;print(json.dumps({n:importlib.metadata.version(n) for n in ('setuptools','wheel')}))"],env=env,text=True,timeout=30))
        if build!=manifest['python_build']:raise ValueError('Python build tool versions differ')
        source=output/'source';release.export_source(source,manifest['epoch'])
        nuget=release.build_config(source,manifest['dotnet']['version'])
        for component,project in (('askpass','EnclaveAskpass.csproj'),('runtime','EnclaveRuntime.csproj')):
            with (output/(component+'-build.log')).open('xb') as log:
                p=subprocess.run([dotnet,'build',str(source/'native'/component/project),'-c','Release','-o',str(output/component),'--nologo','-p:RestoreConfigFile='+str(nuget)],cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=180)
            if p.returncode:raise RuntimeError('Isolated host helper build failed')
        helper=output/'askpass/egw-askpass.dll';askpass_probe(dotnet,helper,env)
        # A similarly named generic runtime must never satisfy the helper role.
        try:askpass_probe(dotnet,output/'runtime/egw-runtime.dll',env)
        except ValueError:pass
        else:raise ValueError('Generic runtime passed the askpass probe')
        report.update(status='passed',checks=report['checks']+['tool-hashes-versions','isolated-source-exports','dedicated-helper-behavior','wrong-helper-rejected'],
                      helper_sha256=release.digest(helper),runtime_sha256=release.digest(output/'runtime/egw-runtime.dll'))
        env.update(PYTHONPATH=str(ROOT/'src'),EGW_TEST_POWERSHELL=powershell,EGW_TEST_DOTNET=dotnet,EGW_TEST_HELPER=str(helper))
        return env
    except BaseException as e:report.update(status='failed',error_type=type(e).__name__);raise
    finally:release.write_json(output/'result.json',report)
