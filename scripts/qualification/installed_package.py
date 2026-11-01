#!/usr/bin/env python3
"""Build and accept the actual distribution outside the source import path."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile

ROOT=Path(__file__).resolve().parents[2]


def run(output: Path,pip_wheel: Path|None=None):
    if output.exists() and any(output.iterdir()):raise FileExistsError('Use a new artifact acceptance directory')
    output.mkdir(parents=True,mode=0o700,exist_ok=True)
    output=output.resolve();report={'status':'running','scope':'built-sdist-wheel-clean-installed-cli','runs':[]}
    environment={key:value for key,value in os.environ.items() if key not in ('PYTHONPATH','PYTHONHOME')}
    environment['PYTHONNOUSERSITE']='1'
    if pip_wheel:
        pip_wheel=pip_wheel.resolve()
        with zipfile.ZipFile(pip_wheel) as bundle:
            if 'pip/__main__.py' not in bundle.namelist():raise ValueError('An explicit pip wheel is required')
        report['pip_wheel_sha256']=hashlib.sha256(pip_wheel.read_bytes()).hexdigest()
    def command(label,args,cwd):
        result=subprocess.run(args,cwd=cwd,env=environment,capture_output=True,timeout=180)
        (output/(label+'.log')).write_bytes(result.stdout+result.stderr)
        report['runs'].append({'name':label,'exit_code':result.returncode})
        if result.returncode:raise RuntimeError(label+' failed; inspect its artifact log')
        return result.stdout.decode('utf-8','replace')
    try:
        # Do not sweep an operator's checkout into an sdist. Start from tracked
        # product files, explicitly excluding workflows and private lab state.
        with tempfile.TemporaryDirectory(prefix='egw-artifact-') as temporary, tempfile.TemporaryDirectory(prefix='egw-artctl-',dir='/tmp' if os.name!='nt' else None) as runtime:
            work=Path(temporary).resolve();source=work/'source';source.mkdir()
            # The same checker runs from an exported source tree on Windows;
            # include only Python package inputs, never arbitrary lab contents.
            tracked=['pyproject.toml','README.md','LICENSE']+[str(path.relative_to(ROOT)) for path in (ROOT/'src/enclave_gateway').rglob('*')
                     if path.is_file() and path.suffix in ('.py','.ps1','.xml') and '__pycache__' not in path.parts]
            for name in tracked:
                if not name:continue
                origin=ROOT/name
                if not origin.is_file() or origin.is_symlink():raise ValueError('Invalid distribution source')
                target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(origin,target)
            command('build-sdist',[sys.executable,'-c',"import setuptools.build_meta as b;b.build_sdist("+repr(str(output))+')'],source)
            archive=next(output.glob('*.tar.gz'))
            unpack=work/'unpacked';unpack.mkdir()
            with tarfile.open(archive) as bundle:
                for item in bundle.getmembers():
                    candidate=(unpack/item.name).resolve()
                    if not candidate.is_relative_to(unpack) or not (item.isfile() or item.isdir()):raise ValueError('Unsafe source archive')
                bundle.extractall(unpack,**({'filter':'data'} if sys.version_info>=(3,12) else {}))
            extracted=next(unpack.iterdir())
            command('build-wheel-from-sdist',[sys.executable,'-c',"import setuptools.build_meta as b;b.build_wheel("+repr(str(output))+')'],extracted)
            wheel=next(output.glob('*.whl'))
            with zipfile.ZipFile(wheel) as bundle:
                names=set(bundle.namelist())
                resources={str(path.relative_to(ROOT/'src')).replace(os.sep,'/'):hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in (ROOT/'src/enclave_gateway/agents').glob('*') if path.suffix in ('.ps1','.py')}
                for name,digest in resources.items():
                    if name not in names or hashlib.sha256(bundle.read(name)).hexdigest()!=digest:raise ValueError('Missing or changed runtime resource: '+name)
            venv.EnvBuilder(with_pip=pip_wheel is None).create(work/'venv')
            binary=work/'venv'/('Scripts' if os.name=='nt' else 'bin');python=binary/('python.exe' if os.name=='nt' else 'python')
            clean=work/'outside-source';clean.mkdir()
            if pip_wheel:
                bootstrap="import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
                command('bootstrap-pip',[str(python),'-I','-c',bootstrap,str(pip_wheel),'install','--no-index','--no-deps',str(pip_wheel)],clean)
            command('install',[str(python),'-m','pip','install','--no-index','--no-deps',str(wheel)],clean)
            for entry in ('egw','enclave-gateway'):
                command(entry+'-help',[str(binary/(entry+('.exe' if os.name=='nt' else ''))),'--help'],clean)
            probe='''import hashlib,importlib.metadata,json,pathlib
import enclave_gateway
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.provision.builder import ApplianceProvisioner,ProvisionOptions
p=pathlib.Path(enclave_gateway.__file__).resolve()
assert 'site-packages' in p.parts
assert importlib.metadata.version('enclave-gateway')==enclave_gateway.__version__
m=ApplianceProvisioner(EnclaveConfig()).prepare_bundle(pathlib.Path('seed'),ProvisionOptions(),create_disk=False)
assert {'machine_prepare.ps1','bastion_worker.ps1','bastion_bootstrap.ps1','appliance_init.ps1','session_supervisor.ps1'} <= set(m['copied_agents'])
assert pathlib.Path(m['autounattend_xml']).is_file() and pathlib.Path(m['post_install_ps1']).is_file()
print(json.dumps({'package':str(p),'version':enclave_gateway.__version__,'agents':m['copied_agents']}))
'''
            report['installed']=json.loads(command('installed-provision',[str(python),'-I','-c',probe],clean))
            (clean/'config.json').write_text(json.dumps({'appliance':{'runtime_dir':str(Path(runtime).resolve()),'disk_path':str(clean/'disk.qcow2'),
                'efi_vars_path':str(clean/'efi_vars.fd'),'snapshot_dir':str(clean/'states')},'provider':{'type':'custom'},'bastion':{'enabled':False}}))
            environment['ENCLAVE_APPLIANCE_PASSWORD']=secrets.token_urlsafe(24)
            entry=binary/('egw.exe' if os.name=='nt' else 'egw')
            cli=json.loads(command('installed-cli-init',[str(entry),'-c',str(clean/'config.json'),'--state-dir',str(clean/'controller'),
                                   'init','--output-dir',str(clean/'cli-seed')],clean))
            if cli['disk_created'] or cli['efi_vars_created'] or 'machine_prepare.ps1' not in cli['copied_agents']:raise ValueError('Invalid installed CLI provisioning result')
            report.update(status='passed',resources=len(resources),artifacts={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (archive,wheel)})
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:(output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--pip-wheel',type=Path,help='Explicit offline pip wheel for distributions without ensurepip.')
    args=parser.parse_args();print(json.dumps(run(args.output,args.pip_wheel),indent=2))
