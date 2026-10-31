"""Locate and verify the managed Windows runtime before executing it."""
from __future__ import annotations
import json
import math
import os
import subprocess
from pathlib import Path
from enclave_gateway.security.quoting import ps_quote
from enclave_gateway.operations.context import budget


def verified_runtime(path, signers=(), require_signed=True, expected_sha256="", *, verification_timeout_sec=15.0):
    if not math.isfinite(verification_timeout_sec) or not 0 < verification_timeout_sec <= 120:
        raise ValueError('Invalid signature verification timeout')
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
        shell=str(Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
        result=subprocess.run([shell,'-NoProfile','-NonInteractive','-Command',script],capture_output=True,timeout=budget(verification_timeout_sec,"runtime.signature"))
        if result.returncode: raise PermissionError('Windows runtime signer is not trusted')
    return str(path)
