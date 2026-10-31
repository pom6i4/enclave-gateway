"""Locate and verify the managed Windows runtime before executing it."""
from __future__ import annotations
import json
import os
import subprocess
from pathlib import Path
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.operations.context import budget


def verified_runtime(path, signers=(), require_signed=True, expected_sha256=""):
    path=Path(os.path.expandvars(path.replace('%LOCALAPPDATA%',os.environ.get('LOCALAPPDATA','%LOCALAPPDATA%')))).absolute()
    if not path.is_file(): raise FileNotFoundError('Install the managed Windows runtime')
    if expected_sha256:
        import hashlib,hmac,re
        if not re.fullmatch('[a-fA-F0-9]{64}',expected_sha256): raise ValueError('Invalid native runtime pin')
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                budget(15,'runtime.hash');digest.update(chunk)
        if not hmac.compare_digest(digest.hexdigest(),expected_sha256.lower()): raise PermissionError('Native runtime hash mismatch')
    if require_signed:
        trusted=','.join(ps_quote(item.replace(' ','').upper()) for item in signers)
        script=f"$s=Get-AuthenticodeSignature -LiteralPath {ps_quote(str(path))}; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -notin @({trusted})) {{exit 1}}"
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=budget(15,"runtime.signature"))
        if result.returncode: raise PermissionError('Windows runtime signer is not trusted')
    return str(path)
