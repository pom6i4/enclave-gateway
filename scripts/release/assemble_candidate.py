#!/usr/bin/env python3
"""Assemble or verify a source-bound unsigned kit from explicitly pinned receipts."""
from __future__ import annotations
import argparse
import base64
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2]


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1024*1024),b''):digest.update(data)
    return digest.hexdigest()


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('Duplicate candidate metadata key')
        result[key]=value
    return result


def _json(raw):
    def constant(_):raise ValueError('Non-finite candidate metadata')
    return json.loads(raw,object_pairs_hook=_pairs,parse_constant=constant)


def _ref(value):
    if type(value) is not dict or set(value)!={'path','sha256'} or not isinstance(value['path'],str):
        raise ValueError('Expected an explicit file and SHA-256 reference')
    path=Path(value['path'])
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or not isinstance(value['sha256'],str) or not re.fullmatch('[a-f0-9]{64}',value['sha256'])
            or sha(path)!=value['sha256']):raise ValueError('Candidate input hash/path mismatch')
    return path


def _name(value):
    if (not isinstance(value,str) or not value or '\\' in value or '\0' in value
            or PurePosixPath(value).is_absolute() or any(part in ('','.','..') for part in value.split('/'))):
        raise ValueError('Unsafe candidate member name')
    return value


def inventory(root):
    root=Path(root)
    if root.is_symlink() or not root.is_dir():raise ValueError('Candidate root must be a regular directory')
    result={}
    for path in root.rglob('*'):
        mode=path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('Linked/special candidate file rejected')
        if stat.S_ISREG(mode):result[_name(path.relative_to(root).as_posix())]=sha(path)
    return result


def verify(root):
    root=Path(root);actual=inventory(root);sums=root/'SHA256SUMS'
    if 'SHA256SUMS' not in actual:raise ValueError('Missing candidate checksums')
    expected={}
    for line in sums.read_text(encoding='utf-8').splitlines():
        parts=line.split('  ',1)
        if len(parts)!=2 or not re.fullmatch('[a-f0-9]{64}',parts[0]):raise ValueError('Invalid candidate checksum row')
        name=_name(parts[1])
        if name=='SHA256SUMS' or name in expected:raise ValueError('Duplicate/self-referencing checksum')
        expected[name]=parts[0]
    actual.pop('SHA256SUMS')
    if expected!=actual:raise ValueError('Candidate has missing, changed or unlisted files')
    document=_json((root/'PROVENANCE.json').read_bytes())
    payload={k:v for k,v in actual.items() if k!='PROVENANCE.json'}
    if document.get('payload_sha256')!=payload or document.get('status')!='unsigned-candidate':
        raise ValueError('Candidate provenance differs from delivered payload')
    return {'status':'passed','source_commit':document['source_commit'],'files':len(actual)+1,
            'checksums':'complete exact inventory; integrity is not publisher authentication'}


def acceptance(reports,artifacts,required,qualifier,native_qualifier=None):
    if (type(required) is not list or not required or any(not isinstance(x,str) for x in required)
            or len(set(required))!=len(required)):raise ValueError('Explicit unique acceptance platforms required')
    must={key for prefix,key in (('win-x64/','windows:x86_64'),('win-arm64/','windows:arm64')) if any(name.startswith(prefix) for name in artifacts)}
    if not must<=set(required) or not any(name in ('linux:arm64','linux:x86_64') for name in required):
        raise ValueError('Every delivered Windows target and a Linux platform must be required')
    summaries={}
    wheels=[name for name in artifacts if name.endswith('.whl')]
    if len(wheels)!=1:raise ValueError('Exactly one wheel required')
    wheel=wheels[0]
    for row in reports:
        if (type(row) is not dict or type(row.get('revision')) is not int or row['revision']!=1
                or row.get('status')!='passed' or row.get('scope')!='release-artifact-acceptance'
                or row.get('qualifier_sha256')!=qualifier):raise ValueError('Invalid/stale artifact acceptance receipt')
        platform=row.get('platform',{})
        if type(platform) is not dict or type(row.get('checks')) is not dict:raise ValueError('Invalid platform/check map')
        system=platform.get('system');machine=platform.get('machine')
        if system not in ('Windows','Linux') or machine not in ('arm64','x86_64'):raise ValueError('Unsupported acceptance platform')
        key=system.lower()+':'+machine
        if key in summaries:raise ValueError('Duplicate platform acceptance')
        expected={wheel:artifacts[wheel]};checks=['wheel_install','cli','isolated_import']
        if system=='Windows':
            if native_qualifier is not None and row.get('native_qualifier_sha256')!=native_qualifier:raise ValueError('Stale native qualifier receipt')
            if native_qualifier is not None and row.get('lab_trust_cleanup')!='own key/trust removed; original stores preserved':raise ValueError('Laboratory trust cleanup not verified')
            rid='win-arm64' if machine=='arm64' else 'win-x64'
            for name in ('egw-runtime.exe','egw-askpass.exe'):expected[rid+'/'+name]=artifacts[rid+'/'+name]
            checks+=['native_filesystem','native_cancellation','askpass','sdk_independent','lab_signatures','unsigned_policy_denied']
        else:checks+=['posix_execution','rooted_files','owned_cancellation','mcp_read_only']
        if row.get('artifacts')!=expected or any(row.get('checks',{}).get(check) is not True for check in checks):
            raise ValueError('Acceptance does not cover the exact artifacts and required checks')
        summaries[key]={'platform':key,'artifacts':expected,'checks':checks,'scope':row.get('environment_scope','isolated platform')}
    if set(required)-set(summaries):raise ValueError('Missing required platform acceptance')
    return [summaries[key] for key in sorted(summaries)]


def _git(root,*args):return subprocess.check_output(['git','-C',str(root),*args])


def committed_inputs(root,commit,sources):
    """Ignored and assume-unchanged files cannot masquerade as committed inputs."""
    names=set(sources)|{'LICENSE','CHANGELOG.md','docs/RELEASING.md'};contents={}
    with tarfile.open(fileobj=io.BytesIO(_git(root,'archive','--format=tar',commit))) as archive:
        for member in archive:
            if member.name in names:
                if not member.isfile() or member.name in contents:raise ValueError('Non-regular/duplicate committed release input')
                contents[member.name]=archive.extractfile(member).read()
    if set(contents)!=names or any(hashlib.sha256(contents[name]).hexdigest()!=value for name,value in sources.items()):
        raise ValueError('Build includes bytes absent from the declared Git commit')
    return contents


def assemble(manifest_path,output,root=ROOT):
    manifest=_json(Path(manifest_path).read_bytes());fields={'revision','source_commit','comparison','toolchain','schemas','acceptance','required_platforms','evidence'}
    if type(manifest) is not dict or set(manifest)!=fields or type(manifest['revision']) is not int or manifest['revision']!=1:
        raise ValueError('Invalid candidate assembly manifest')
    if any(type(manifest[name]) is not list for name in ('schemas','acceptance','required_platforms','evidence')):
        raise ValueError('Candidate schema, acceptance and evidence lists must be explicit')
    commit=manifest['source_commit']
    if not isinstance(commit,str) or not re.fullmatch('[a-f0-9]{40}',commit):raise ValueError('Exact committed source required')
    if _git(root,'rev-parse','HEAD').decode().strip()!=commit or _git(root,'status','--porcelain').strip():
        raise ValueError('Assembly requires clean source at the declared commit')
    comparison_path=_ref(manifest['comparison']);toolchain_path=_ref(manifest['toolchain'])
    output=Path(output)
    if not output.is_absolute():raise ValueError('Use an absolute candidate output outside source/build/cache trees')
    destination=output.resolve()
    toolchain=_json(toolchain_path.read_bytes())
    protected=[Path(root).resolve(),comparison_path.parent.resolve(),Path(toolchain['nuget_packages']).resolve()]
    if any(destination.is_relative_to(path) for path in protected):raise ValueError('Candidate output must be outside source/build/cache trees')
    if output.exists():raise FileExistsError('Preserve earlier candidate outputs')
    report=_json(comparison_path.read_bytes());toolchain=_json(toolchain_path.read_bytes())
    if report.get('status')!='passed' or report.get('manifest_sha256')!=sha(toolchain_path):raise ValueError('Failed/unbound reproducible comparison')
    sources=report.get('sources')
    if type(sources) is not dict or 'scripts/release/reproducible_build.py' not in sources:raise ValueError('Missing committed build source inventory')
    committed=committed_inputs(root,commit,sources)
    if sha(root/'scripts/release/reproducible_build.py')!=sources['scripts/release/reproducible_build.py']:raise ValueError('Build tool differs from committed source')
    # Import from the same checked-out source, never from a caller-selected module.
    import importlib.util
    spec=importlib.util.spec_from_file_location('candidate_release_build',root/'scripts/release/reproducible_build.py')
    release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
    if report.get('sources')!={p.relative_to(root).as_posix():sha(p) for p in release.source_files(root)}:
        raise ValueError('Build sources differ from the committed candidate')
    artifacts=report.get('artifacts');first=comparison_path.parent/'first/artifacts';second=comparison_path.parent/'second/artifacts'
    if type(artifacts) is not dict or not artifacts or inventory(first)!=artifacts or inventory(second)!=artifacts:
        raise ValueError('Independent artifact trees differ from their receipt')
    targets=toolchain.get('runtimes')
    if (type(targets) is not list or not targets or any(x not in ('win-x64','win-arm64') for x in targets)
            or len(set(targets))!=len(targets)):raise ValueError('Invalid candidate Windows targets')
    python_files={name for name in artifacts if '/' not in name}
    from_types=[name for name in python_files if name.endswith('.whl') or name.endswith('.tar.gz')]
    package_files={'egw-askpass.exe','egw-runtime.exe','bastion_worker.ps1','bastion_bootstrap.ps1',
                   'appliance_init.ps1','session_supervisor.ps1','verify_windows.ps1','install_windows.ps1','unsigned-manifest.json'}
    expected_files=python_files|{rid+'/'+name for rid in targets for name in package_files}
    if len(python_files)!=2 or len(from_types)!=2 or sum(name.endswith('.whl') for name in python_files)!=1 or set(artifacts)!=expected_files:
        raise ValueError('Unexpected or incomplete artifact package allow-list')
    receipts=[_json(_ref(ref).read_bytes()) for ref in manifest['acceptance']]
    summaries=acceptance(receipts,artifacts,manifest['required_platforms'],sha(root/'scripts/qualification/artifact_acceptance.py'),sha(root/'scripts/qualification/native_windows.py'))
    evidence={}
    for item in manifest['evidence']:
        if type(item) is not dict or set(item)!={'name','file'} or not isinstance(item['name'],str) or not re.fullmatch('[a-z][a-z0-9-]{0,63}',item['name']) or item['name'] in evidence:
            raise ValueError('Invalid candidate evidence identifier')
        _ref(item['file']);evidence[item['name']]=item['file']['sha256']
    try:
        from jsonschema import Draft7Validator
        from referencing import Registry,Resource
    except ImportError as error:raise RuntimeError('Install the optional release dependencies: pip install .[release]') from error
    schemas=[_json(_ref(ref).read_bytes()) for ref in manifest['schemas']]
    registry=Registry().with_resources([(value['$id'],Resource.from_contents(value)) for value in schemas])
    schema=next((value for value in schemas if value.get('$id')=='http://cyclonedx.org/schema/bom-1.6.schema.json'),None)
    if schema is None:raise ValueError('Pinned CycloneDX 1.6 schema required')
    bom=_json((comparison_path.parent/'sbom.cdx.json').read_bytes())
    if sha(comparison_path.parent/'sbom.cdx.json')!=report.get('sbom_sha256'):raise ValueError('SBOM changed after comparison')
    Draft7Validator(schema,registry=registry).validate(bom)
    required=[row for row in bom['components'] if row.get('scope')=='required']
    expected={prefix+rid for rid in targets for prefix in ('Microsoft.NETCore.App.Runtime.','Microsoft.NETCore.App.Host.')}
    if {row['name'] for row in required}!=expected:raise ValueError('SBOM runtime scope differs from delivered targets')
    licenses={rid:{} for rid in targets};notices=[]
    for item in required:
        name,version=item['name'],item['version'];package=Path(toolchain['nuget_packages'])/name.lower()/version/(name.lower()+'.'+version+'.nupkg')
        if version!=toolchain['runtime_version']:raise ValueError('SBOM runtime version differs from pinned toolchain')
        if package.is_symlink():raise ValueError('Linked dependency archive rejected')
        raw=package.read_bytes()
        if base64.b64encode(hashlib.sha512(raw).digest()).decode()!=report['dependencies'][name+'/'+version]:raise ValueError('Dependency archive differs from build receipt')
        rid=next(rid for rid in targets if name.endswith('.'+rid))
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names=[n for n in archive.namelist() if n.upper() in ('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT')]
            if len(names)!=2:raise ValueError('Runtime license/notices missing or duplicated')
            for n in names:
                content=archive.read(n);member='licenses/'+name+'/'+n;licenses[rid][member]=content
                notices.append({'package':name,'version':version,'target':rid,'path':member,'sha256':hashlib.sha256(content).hexdigest()})
    epoch=toolchain['epoch']
    if type(epoch) is not int or not 315532800<=epoch<=4102444800:raise ValueError('Invalid candidate source epoch')
    output=Path(output)
    if output.exists():raise FileExistsError('Preserve earlier candidate outputs')
    output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    def put(name,content):
        p=output/_name(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
    wheel=next(p for p in first.iterdir() if p.name.endswith('.whl'))
    with zipfile.ZipFile(wheel) as archive:
        names=[n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
        if len(names)!=1:raise ValueError('Ambiguous Python wheel metadata')
        metadata=BytesParser().parsebytes(archive.read(names[0]));version=metadata['Version']
        if metadata['Name']!='enclave-gateway' or metadata['License-Expression']!='MIT':raise ValueError('Invalid candidate Python identity/license')
    for p in first.iterdir():
        if p.is_file():put('python/'+p.name,p.read_bytes())
    source_name='source/enclave-gateway-source-'+commit[:12]+'.tar.gz';tar=_git(root,'archive','--format=tar','--prefix=enclave-gateway-'+commit[:12]+'/',commit);compressed=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=compressed,mtime=0,compresslevel=9) as stream:stream.write(tar)
    put(source_name,compressed.getvalue());containers=[source_name]
    for rid in targets:
        entries={p.name:p.read_bytes() for p in (first/rid).iterdir()};entries.update(licenses[rid]);entries['LICENSE']=committed['LICENSE'];zipped=io.BytesIO()
        with zipfile.ZipFile(zipped,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            for name,content in sorted(entries.items()):
                entry=zipfile.ZipInfo(_name(name),time.gmtime(epoch)[:6]);entry.create_system=3;entry.external_attr=0o100644<<16;entry.compress_type=zipfile.ZIP_DEFLATED;archive.writestr(entry,content,compresslevel=9)
        name='windows/enclave-gateway-'+rid+'-unsigned.zip';put(name,zipped.getvalue());containers.append(name)
    for name in ('LICENSE','CHANGELOG.md'):put(name,committed[name])
    table='\n'.join(line for line in committed['docs/RELEASING.md'].decode('utf-8').splitlines() if line.startswith('|'))
    put('COMPATIBILITY.md',('# Component compatibility\n\n'+table+'\n').encode())
    bom['metadata']['properties']=[*bom['metadata'].get('properties',[]),{'name':'release:source-commit','value':commit},{'name':'release:signing','value':'unsigned'}]
    for name in containers:
        ref='kit:'+name;bom['components'].append({'type':'file','bom-ref':ref,'name':name,'hashes':[{'alg':'SHA-256','content':sha(output/name)}]});bom['dependencies'][0]['dependsOn'].append(ref)
    Draft7Validator(schema,registry=registry).validate(bom)
    put('SBOM.cdx.json',(json.dumps(bom,sort_keys=True,indent=2)+'\n').encode())
    text=f'''# Enclave Gateway {version} unsigned candidate

Source: `{commit}`. Verify SHA256SUMS with a trusted SHA-256 tool before use.
Checksums are integrity evidence, not publisher authentication.

Install python/{wheel.name} in an approved Python 3.10+ venv with
`python -m pip install --no-index --no-deps python/{wheel.name}`.
Standard runspace/key-based use needs no custom worker executable.
Windows ZIPs retain project/runtime licenses and are deliberately unsigned.
Production Enterprise requires independently approved signing and release ordering.
Laboratory signatures used during acceptance are not distributed trust anchors.

Extract {source_name} for source, configuration, tests and release/security guides.
PROVENANCE.json records exact artifact acceptance scopes, including virtualization
or container boundaries. Those results do not qualify client VPN drivers, real
keys, production PKI, physical TPM, every host platform or WAN performance.
No release tag, package upload or repository visibility change is performed.
'''
    put('README.md',text.encode())
    payload=inventory(output)
    provenance={'revision':1,'status':'unsigned-candidate','package_version':version,'source_commit':commit,
                'source_tree':_git(root,'rev-parse','HEAD^{tree}').decode().strip(),'source_epoch':epoch,
                'payload_sha256':payload,'acceptance':summaries,'licenses':notices,'evidence_sha256':evidence,
                'comparison_sha256':manifest['comparison']['sha256'],'manifest_sha256':sha(manifest_path),
                'toolchain':{name:{k:toolchain[name][k] for k in ('version','sha256')} for name in ('python','dotnet')},
                'runtime_version':toolchain['runtime_version'],'targets':targets,'reproducibility':{'status':'passed','independent_builds':2,'raw_artifact_files':len(artifacts)},
                'boundaries':['Unsigned/unpublished; laboratory trust is not a production signer','Exact tested artifact scopes only; no client contour or real keys','No physical TPM, proprietary provider, production PKI or WAN acceptance']}
    put('PROVENANCE.json',(json.dumps(provenance,sort_keys=True,indent=2)+'\n').encode())
    checksums=inventory(output);put('SHA256SUMS',''.join(value+'  '+name+'\n' for name,value in sorted(checksums.items())).encode())
    if _git(root,'rev-parse','HEAD').decode().strip()!=commit or _git(root,'status','--porcelain').strip():raise RuntimeError('Source changed during assembly')
    return verify(output)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    create=sub.add_parser('assemble');create.add_argument('--manifest',type=Path,required=True);create.add_argument('--output',type=Path,required=True)
    check=sub.add_parser('verify');check.add_argument('--candidate',type=Path,required=True)
    args=parser.parse_args();result=assemble(args.manifest,args.output) if args.action=='assemble' else verify(args.candidate);print(json.dumps(result,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
