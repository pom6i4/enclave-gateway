"""Bind an externally signed lab worker to the unchanged source script body."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]


def worker_artifact(path=None):
    source=ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'
    if path is None:return source
    path=Path(path)
    def body(data):
        text=data.decode('utf-8-sig').replace('\r\n','\n')
        marker='\n# SIG # Begin signature block'
        if marker in text:
            text,signature=text.split(marker,1)
            lines=signature.strip().splitlines()
            if (not lines or lines[-1]!='# SIG # End signature block' or
                any(line and not line.startswith('#') for line in lines) or
                signature.count('# SIG # End signature block')!=1):raise ValueError('Invalid signature comment block')
        return text.rstrip('\n')
    if body(path.read_bytes())!=body(source.read_bytes()):raise ValueError('Signed worker body differs from current source')
    return path
