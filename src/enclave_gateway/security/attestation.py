"""Fresh worker evidence checked against administrator-pinned release identity."""
from __future__ import annotations
import hmac
import re
from enclave_gateway.operations.context import OperationError


def verify(evidence, nonce, *, expected_sha256, trusted_signers=(), require_signed=True,
           expected_account='', require_process_isolation=False,expected_runtime_sha256='',expected_version='0.3.0',
           expected_execution_profile='',expected_policy_sha256='',expected_execution_model=''):
    def require(condition, reason):
        if not condition: raise OperationError('agent_attestation_failed','attestation',node='@bastion',message=reason)
    require(isinstance(evidence,dict),'Worker evidence is not an object')
    require(evidence.get('protocol_revision')==1,'Unsupported attestation protocol')
    require(evidence.get('version')==expected_version,'Worker version mismatch')
    require(isinstance(evidence.get('nonce'),str) and hmac.compare_digest(evidence['nonce'],nonce),'Stale or mismatched challenge')
    require(bool(re.fullmatch('[a-fA-F0-9]{64}',expected_sha256 or '')),'Pin a release worker hash in trusted configuration')
    require(evidence.get('loaded_sha256')==expected_sha256.lower(),'Running worker does not match pinned release')
    require(evidence.get('current_sha256')==evidence.get('loaded_sha256'),'Worker file changed since startup')
    require(bool(re.fullmatch('[a-f0-9]{32}',evidence.get('instance_id',''))),'Missing worker instance identity')
    if expected_execution_profile:
        require(evidence.get('execution_profile')==expected_execution_profile,'Worker execution profile mismatch')
    if expected_execution_model:
        require(evidence.get('execution_model') == expected_execution_model,'Worker OpenSSH backend mismatch')
    if expected_policy_sha256:
        require(evidence.get('policy_sha256')==expected_policy_sha256,'Worker policy does not match the independently approved pin')
    if require_signed:
        require(evidence.get('signature_status')=='Valid','Worker startup signature was not valid')
        require(evidence.get('loaded_signature_status')=='Valid','Worker was not trusted at startup')
        require(evidence.get('loaded_signer','')==evidence.get('signer',''),'Worker signing identity changed')
        require(evidence.get('signer','').upper() in {item.replace(' ','').upper() for item in trusted_signers},'Worker publisher is not trusted')
    if expected_account:
        require(bool(re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+',expected_account)),'Pin the Windows SID rather than an account display name')
        require(expected_account==evidence.get('sid'),'Worker OS account mismatch')
    if require_process_isolation:
        require(evidence.get('execution_model')=='owned-process-job','Worker does not isolate payload process trees')
        require(bool(re.fullmatch('[a-fA-F0-9]{64}',expected_runtime_sha256 or '')),'Pin the approved runtime hash')
        if require_signed:
            require(evidence.get('runtime_signature_status')=='Valid' and evidence.get('runtime_signer','').upper() in {item.replace(' ','').upper() for item in trusted_signers},'Runtime signature is not trusted')
        require(evidence.get('runtime_loaded_sha256')==expected_runtime_sha256.lower() and evidence.get('runtime_current_sha256')==expected_runtime_sha256.lower(),'Runtime binary changed or does not match the pinned release')
    return {**evidence,'verified':True,'verified_checks':{'nonce':True,'hash':True,'version':True,'signer':require_signed,'account':bool(expected_account),'process_isolation':require_process_isolation},'trust_boundary':'approved-worker-and-protected-control-channel'}
