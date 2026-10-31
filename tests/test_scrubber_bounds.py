"""Large scripts and malformed credential-shaped tokens have bounded processing."""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from enclave_gateway.security.secrets import SecretScrubber


class ScrubberBoundsTests(unittest.TestCase):
    def test_registered_fragments_cannot_hide_structured_secret_delimiters(self):
        token='eyJ'+'a'*20+'.eyJ'+'b'*20+'.'+'c'*20
        text='-----BEGIN PRIVATE KEY-----\nprivate-fixture\n-----END PRIVATE KEY----- '+token+' https://user:uri-fixture@host.enclave.internal'
        result=SecretScrubber(['PRIVATE','eyJ',':']).scrub(text)
        for value in ('private-fixture',token,'uri-fixture'):
            self.assertNotIn(value,result)

    def test_large_tokens_do_not_delay_execution_or_leak_uri_passwords(self):
        code="""
from enclave_gateway.security.secrets import SecretScrubber
large='x'*200000
malformed='eyJaaaaaaaaaaaa-'*10000+'.eyJaaaaaaaaaaaa.short'
uri_noise='scheme://u:p'*10000+' trailing-space @'
value=large+' '+malformed+' '+uri_noise+' https://user:private-fixture@host.enclave.internal/path'
result=SecretScrubber().scrub(value)
assert result.startswith(large+' '+malformed+' '+uri_noise)
assert 'private-fixture' not in result
assert 'https://user:[REDACTED]@host.enclave.internal/path' in result
"""
        environment={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,env=environment,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_embedded_jwt_and_multiple_uri_credentials_are_redacted(self):
        token='eyJ'+'a'*20+'.eyJ'+'b'*20+'.'+'c'*20
        text='prefix-'+token+' https://one:first@host.enclave.internal https://two:second@host.enclave.internal'
        result=SecretScrubber().scrub(text)
        self.assertNotIn(token,result)
        self.assertNotIn('first',result)
        self.assertNotIn('second',result)
        self.assertIn('[REDACTED_JWT]',result)

    def test_repeated_unclosed_private_key_headers_are_bounded(self):
        code="""
from enclave_gateway.security.secrets import SecretScrubber
text='-----BEGIN PRIVATE KEY-----\\n'*20000+'private-fixture'
result=SecretScrubber().scrub(text)
assert result=='[REDACTED_PRIVATE_KEY]'+'\\n'*20000
complete='before\\n-----BEGIN RSA PRIVATE KEY-----\\nprivate-fixture\\n-----END RSA PRIVATE KEY-----\\nafter'
result=SecretScrubber().scrub(complete)
assert result=='before\\n[REDACTED_PRIVATE_KEY]\\n\\n\\nafter'
"""
        environment={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,env=environment,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
