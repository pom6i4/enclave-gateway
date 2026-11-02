#!/usr/bin/env python3
"""Build unsigned artifacts twice from allow-listed, isolated source exports."""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]


def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def write_json(path,value):
    Path(path).write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')


def build_config(source,version):
    write_json(source/'global.json',{'sdk':{'version':version,'rollForward':'disable'}})
    for name in ('Directory.Build.props','Directory.Build.targets'):(source/name).write_text('<Project />\n')
    # An explicit config prevents inherited private feeds/credentials.
    config=source/'NuGet.Config'
    config.write_text('<configuration><packageSources><clear/><add key="public" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>\n')
    return config


def source_files(root=ROOT):
    files=[root/n for n in ('README.md','LICENSE','pyproject.toml')]
    for top,suffixes in (('src',{'.py','.ps1','.xml'}),('native',{'.cs','.csproj'}),('scripts/release',{'.py','.ps1'})):
        files += [p for p in (root/top).rglob('*') if p.is_file() and p.suffix in suffixes
                  and not set(p.relative_to(root).parts)&{'obj','bin','__pycache__'}]
    if any(p.is_symlink() for p in files):raise ValueError('Source links are not build inputs')
    return sorted(set(files))


def export_source(destination,epoch,root=ROOT):
    destination.mkdir(parents=True,mode=0o700)
    for p in source_files(root):
        q=destination/p.relative_to(root);q.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(p,q);q.chmod(0o644);os.utime(q,(epoch,epoch))


def canonical_sdist(source,destination,epoch):
    """Canonical container metadata; member contents must remain byte-identical."""
    with tarfile.open(source) as archive:
        members=archive.getmembers()
        if len({m.name for m in members})!=len(members):raise ValueError('Duplicate sdist member')
        with destination.open('xb') as f,gzip.GzipFile(filename='',fileobj=f,mode='wb',mtime=epoch) as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as out:
            for member in sorted(members,key=lambda m:m.name):
                parts=Path(member.name).parts
                if member.name.startswith('/') or '..' in parts or not (member.isfile() or member.isdir()):raise ValueError('Unsafe sdist member')
                data=archive.extractfile(member).read() if member.isfile() else None
                item=tarfile.TarInfo(member.name);item.type=tarfile.REGTYPE if data is not None else tarfile.DIRTYPE
                item.size=len(data) if data is not None else 0;item.mode=0o644 if data is not None else 0o755;item.mtime=epoch
                out.addfile(item,io.BytesIO(data) if data is not None else None)


def verify_equal(first,second):
    a={str(p.relative_to(first)):digest(p) for p in first.rglob('*') if p.is_file()}
    b={str(p.relative_to(second)):digest(p) for p in second.rglob('*') if p.is_file()}
    if not a or a!=b:raise ValueError('Independent unsigned release builds differ')
    return a


def verify_package(package):
    expected=package.with_suffix('.nupkg.sha512').read_text().strip()
    actual=base64.b64encode(hashlib.sha512(package.read_bytes()).digest()).decode()
    if actual!=expected:raise ValueError('Cached runtime archive content changed')
    # NuGet may reuse expanded cache files; checking the archive alone would
    # miss a stale or modified native/runtime payload beside that archive.
    with zipfile.ZipFile(package) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.startswith(('runtimes/','data/','build/')):continue
            target=package.parent/entry.filename
            if '..' in Path(entry.filename).parts or target.is_symlink() or not target.resolve().is_relative_to(package.parent.resolve()) or not target.is_file():raise ValueError('Invalid expanded runtime payload')
            with archive.open(entry) as f:
                h=hashlib.sha256()
                for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
            if digest(target)!=h.hexdigest():raise ValueError('Expanded runtime package differs from its archive')
    return expected


def tool_environment(manifest):
    env={k:v for k,v in os.environ.items() if not k.startswith(('EGW_','ENCLAVE_','SSH_','NUGET_','MSBUILD','DOTNET_','PYTHON'))}
    env.update(DOTNET_ROOT=str(Path(manifest['dotnet']['path']).resolve().parent),DOTNET_CLI_HOME=str(Path(manifest['dotnet_home']).resolve()),DOTNET_CLI_TELEMETRY_OPTOUT='1',DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1',
               DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true',NUGET_PACKAGES=str(Path(manifest['nuget_packages']).resolve()),PYTHONNOUSERSITE='1',
               SOURCE_DATE_EPOCH=str(manifest['epoch']))
    return env


def checked_tool(item,args,env):
    # Preserve a venv's executable entry point while hashing its target bytes.
    path=Path(item['path']).expanduser().absolute()
    if not path.is_file() or digest(path)!=item['sha256']:raise ValueError('Tool digest mismatch')
    value=subprocess.check_output([str(path),*args],env=env,text=True,timeout=30).strip()
    if value!=item['version']:raise ValueError('Tool version mismatch')
    return str(path)


def build(manifest_path,output):
    manifest_path=manifest_path.resolve();output=output.resolve()
    manifest=json.loads(manifest_path.read_text());epoch=manifest['epoch']
    if not manifest['runtimes'] or len(set(manifest['runtimes']))!=len(manifest['runtimes']) or set(manifest['runtimes'])-{'win-x64','win-arm64'}:raise ValueError('Explicit unique Windows build targets required')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',manifest['runtime_version']):raise ValueError('Exact runtime patch required')
    if type(epoch) is not int or not 315532800<=epoch<=4102444800:raise ValueError('Explicit ZIP-compatible source epoch required')
    if output.exists():raise FileExistsError('Use a new build directory')
    output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    env=tool_environment(manifest)
    report={'status':'running','scope':'independent-unsigned-release-builds','manifest_sha256':digest(manifest_path),'attempts':[]}
    def command(label,argv,cwd):
        with (output/(label+'.log')).open('xb') as f:r=subprocess.run(argv,cwd=cwd,env=env,stdout=f,stderr=subprocess.STDOUT,timeout=600)
        if r.returncode:raise RuntimeError('Build step failed: '+label)
    try:
        python=checked_tool(manifest['python'],['-c','import platform;print(platform.python_version())'],env)
        dotnet=checked_tool(manifest['dotnet'],['--version'],env)
        versions=json.loads(subprocess.check_output([python,'-c',"import importlib.metadata,json;print(json.dumps({n:importlib.metadata.version(n) for n in ('setuptools','wheel')}))"],env=env,text=True))
        if versions!=manifest['python_build']:raise ValueError('Python build tool versions differ')
        sources={str(p.relative_to(ROOT)):digest(p) for p in source_files()}
        dependencies={}
        for attempt in ('first','second'):
            work=output/attempt;src=work/'source';export_source(src,epoch);artifacts=work/'artifacts';artifacts.mkdir()
            nuget=build_config(src,manifest['dotnet']['version'])
            python_source=work/'python-source';python_source.mkdir()
            for p in source_files(src):
                rel=p.relative_to(src)
                if rel.parts[0] not in ('native','scripts'):
                    q=python_source/rel;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q);os.utime(q,(epoch,epoch))
            raw=work/'python-raw';raw.mkdir()
            command(attempt+'-sdist',[python,'-c',f'import setuptools.build_meta as b;b.build_sdist({str(raw)!r})'],python_source)
            archive=next(raw.glob('*.tar.gz'));canonical_sdist(archive,artifacts/archive.name,epoch)
            unpack=work/'unpacked';unpack.mkdir()
            with tarfile.open(artifacts/archive.name) as bundle:
                for member in bundle.getmembers():
                    if not (unpack/member.name).resolve().is_relative_to(unpack.resolve()):raise ValueError('Unsafe canonical sdist')
                bundle.extractall(unpack,**({'filter':'data'} if __import__('sys').version_info>=(3,12) else {}))
            command(attempt+'-wheel',[python,'-c',f'import setuptools.build_meta as b;b.build_wheel({str(artifacts)!r})'],next(unpack.iterdir()))
            for rid in manifest['runtimes']:
                if rid not in ('win-x64','win-arm64'):raise ValueError('Unsupported release target')
                executables={}
                for component,project in (('askpass','EnclaveAskpass.csproj'),('runtime','EnclaveRuntime.csproj')):
                    project=src/'native'/component/project;dest=work/(rid+'-'+component)
                    common=['-r',rid,'-p:RuntimeFrameworkVersion='+manifest['runtime_version'],'-p:SelfContained=true','-p:PublishSingleFile=true']
                    command(attempt+'-'+rid+'-'+component+'-restore',[dotnet,'restore',str(project),'--configfile',str(nuget),'--use-lock-file',*common],src)
                    lock=project.parent/'packages.lock.json';lock_before=digest(lock)
                    command(attempt+'-'+rid+'-'+component+'-locked',[dotnet,'restore',str(project),'--configfile',str(nuget),'--locked-mode',*common],src)
                    if digest(lock)!=lock_before:raise ValueError('Restore changed its dependency lock')
                    assets=json.loads((project.parent/'obj/project.assets.json').read_text())
                    for name,lib in assets['libraries'].items():dependencies[name]=lib.get('sha512','')
                    for framework in assets['project']['frameworks'].values():
                        for dep in framework.get('downloadDependencies',[]):
                            versions_=[v.strip() for v in dep['version'].strip('[]').split(',')]
                            if len(set(versions_))!=1:raise ValueError('A runtime download is not exactly pinned')
                            name=dep['name'];v=versions_[0];package=Path(env['NUGET_PACKAGES'])/name.lower()/v/(name.lower()+'.'+v+'.nupkg')
                            dependencies[name+'/'+v]=verify_package(package)
                    command(attempt+'-'+rid+'-'+component,[dotnet,'publish',str(project),'--no-restore','-c','Release','-o',str(dest),*common,'-p:DebugType=none','-p:ContinuousIntegrationBuild=true','-p:PathMap='+str(src)+'=/_/src'],src)
                    executables[component]=dest/('egw-'+component+'.exe')
                import importlib.util
                spec=importlib.util.spec_from_file_location('package_prepare',ROOT/'scripts/release/prepare_package.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                module.prepare(artifacts/rid,executables['askpass'],executables['runtime'])
            report['attempts'].append({'name':attempt,'raw_sdist_sha256':digest(archive),'canonical_sdist_sha256':digest(artifacts/archive.name)})
        files=verify_equal(output/'first/artifacts',output/'second/artifacts')
        version=re.search(r'__version__\s*=\s*[\'"]([^\'"]+)',(ROOT/'src/enclave_gateway/__init__.py').read_text()).group(1)
        components=[{'type':'file','bom-ref':'file:'+name,'name':name,'hashes':[{'alg':'SHA-256','content':value}]} for name,value in sorted(files.items())]
        for name,sha512 in sorted(dependencies.items()):
            package,version_=name.rsplit('/',1)
            embedded=package.lower().startswith(('microsoft.netcore.app.runtime.','microsoft.netcore.app.host.'))
            components.append({'type':'library','bom-ref':'nuget:'+name,'name':package,'version':version_,'purl':'pkg:nuget/'+package+'@'+version_,
                               'scope':'required' if embedded else 'excluded','hashes':[{'alg':'SHA-512','content':base64.b64decode(sha512,validate=True).hex()}],
                               'properties':[{'name':'release:role','value':'embedded-runtime-material' if embedded else 'restore-only-material'}]})
        build_tools=[{'type':'application','name':n,'version':v} for n,v in sorted({'.NET SDK':manifest['dotnet']['version'],'Python':manifest['python']['version'],**versions}.items())]
        sbom={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'metadata':{'component':{'type':'application','bom-ref':'enclave-gateway','name':'enclave-gateway','version':version,'licenses':[{'license':{'id':'MIT'}}]},'tools':{'components':build_tools}},
              'components':components,'dependencies':[{'ref':'enclave-gateway','dependsOn':[c['bom-ref'] for c in components]}]}
        write_json(output/'sbom.cdx.json',sbom)
        report.update(status='passed',sources=sources,artifacts=files,dependencies=dependencies,sbom_sha256=digest(output/'sbom.cdx.json'),
                      archives='canonical-container-metadata-content-preserved',signing='unsigned',production_acceptance=False)
        if sources!={str(p.relative_to(ROOT)):digest(p) for p in source_files()}:raise RuntimeError('Build source changed during comparison')
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:write_json(output/'result.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();print(json.dumps(build(args.manifest,args.output),indent=2))
