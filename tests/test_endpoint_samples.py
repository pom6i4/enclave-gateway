"""Exact endpoint evidence must survive source removal and reject substitutions."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/qualification/preserve_endpoint_samples.py'
spec = importlib.util.spec_from_file_location('endpoint_samples', SCRIPT)
samples = importlib.util.module_from_spec(spec)
spec.loader.exec_module(samples)


class EndpointSampleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.worker = self.root / 'approved.ps1'
        self.policy = self.root / 'approved.json'
        self.worker.write_bytes(b'\xef\xbb\xbfthrow "must never execute"\r\n# exact bytes\r\n')
        self.policy.write_bytes(b'{"revision":1}\r\n')
        self.worker_hash = hashlib.sha256(self.worker.read_bytes()).hexdigest()
        self.policy_hash = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.bundle = self.root / 'attempt001'

    def capture(self):
        return samples.capture(self.worker, self.worker_hash, self.policy, self.policy_hash, self.bundle)

    def verify(self):
        return samples.verify_bundle(self.bundle, self.worker_hash, self.policy_hash)

    def test_exact_binary_capture_survives_source_removal(self):
        original = self.worker.read_bytes()
        manifest = self.capture()
        self.worker.unlink()
        self.policy.unlink()
        self.assertEqual((self.bundle / 'worker.ps1').read_bytes(), original)
        self.assertEqual(self.verify(), manifest)
        self.assertEqual(manifest['authenticode_verification'], 'not_performed')
        self.assertEqual(manifest['kes_acceptance'], 'not_performed')
        self.assertNotIn(str(self.root), json.dumps(manifest))

    def test_existing_capture_is_never_overwritten(self):
        self.capture()
        before = {p.name: p.read_bytes() for p in self.bundle.iterdir()}
        with self.assertRaises(FileExistsError):
            self.capture()
        self.assertEqual({p.name: p.read_bytes() for p in self.bundle.iterdir()}, before)

    def test_independent_pins_are_required_before_any_output(self):
        for invalid in ('', 'abc', 'g' * 64, 'a' * 64):
            with self.subTest(pin=invalid), self.assertRaises(ValueError):
                samples.capture(self.worker, invalid, self.policy, self.policy_hash, self.bundle)
            self.assertFalse(self.bundle.exists())
        self.worker_hash = self.worker_hash.upper()
        self.assertEqual(self.capture()['files']['worker.ps1']['sha256'], self.worker_hash.lower())

    def test_policy_pin_mismatch_does_not_create_output(self):
        self.policy_hash = '0' * 64
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.bundle.exists())

    def test_changed_sample_and_rewritten_manifest_cannot_replace_approved_pin(self):
        self.capture()
        changed = b'resigned sample'
        (self.bundle / 'worker.ps1').write_bytes(changed)
        manifest_path = self.bundle / 'manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        manifest['files']['worker.ps1'] = samples.file_record(changed)
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(ValueError):
            self.verify()

    def test_extra_or_incomplete_files_reject_bundle(self):
        self.capture()
        extra = self.bundle / 'unexpected.txt'
        extra.write_text('not an approved export')
        with self.assertRaises(ValueError):
            self.verify()
        extra.unlink()
        (self.bundle / 'policy.json').unlink()
        with self.assertRaises(ValueError):
            self.verify()

    def test_malformed_manifest_is_rejected(self):
        self.capture()
        manifest_path = self.bundle / 'manifest.json'
        for invalid in (b'[]', b'{"files": null}', b'not json'):
            manifest_path.write_bytes(invalid)
            with self.assertRaises(ValueError):
                self.verify()

    def test_oversized_source_rejected_before_output(self):
        with patch.object(samples, 'MAX_SAMPLE_BYTES', 8), self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.bundle.exists())

    def test_directory_and_wrong_extension_are_rejected(self):
        self.worker.unlink()
        self.worker.mkdir()
        with self.assertRaises(ValueError):
            self.capture()
        self.worker = self.root / 'private.key'
        self.worker.write_bytes(b'not a worker')
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.bundle.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink and FIFO boundaries')
    def test_symlink_and_fifo_sources_do_not_open(self):
        real = self.root / 'real.ps1'
        self.worker.rename(real)
        self.worker.symlink_to(real)
        with self.assertRaises(ValueError):
            self.capture()
        self.worker.unlink()
        os.mkfifo(self.worker)
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.bundle.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink boundaries')
    def test_symlink_bundle_and_saved_sample_are_rejected(self):
        self.bundle.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.capture()
        self.bundle.unlink()
        self.capture()
        (self.bundle / 'worker.ps1').unlink()
        (self.bundle / 'worker.ps1').symlink_to(self.worker)
        with self.assertRaises(ValueError):
            self.verify()

    @unittest.skipUnless(os.name == 'posix', 'POSIX permission checks')
    def test_private_parent_and_outputs(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse(self.bundle.exists())
        self.root.chmod(0o700)
        self.capture()
        self.assertEqual(self.bundle.stat().st_mode & 0o777, 0o700)
        for path in self.bundle.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        (self.bundle / 'policy.json').chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify()

    def test_io_failure_retains_incomplete_capture(self):
        write = samples.write_new

        def fail_policy(path, data):
            if path.name == 'policy.json':
                raise OSError('simulated storage failure')
            write(path, data)

        with patch.object(samples, 'write_new', side_effect=fail_policy), self.assertRaises(OSError):
            self.capture()
        self.assertEqual((self.bundle / 'worker.ps1').read_bytes(), self.worker.read_bytes())
        self.assertEqual(json.loads((self.bundle / 'capture-failure.json').read_bytes())['status'], 'failed')
        with self.assertRaises(ValueError):
            self.verify()
        with self.assertRaises(FileExistsError):
            self.capture()

    def test_cli_capture_verify_and_private_failure_output(self):
        common = ['--worker-sha256', self.worker_hash, '--policy-sha256', self.policy_hash]
        saved = subprocess.run([sys.executable, str(SCRIPT), 'capture', '--worker', str(self.worker),
                                '--policy', str(self.policy), '--output', str(self.bundle), *common], capture_output=True, text=True)
        self.assertEqual(saved.returncode, 0, saved.stderr)
        verified = subprocess.run([sys.executable, str(SCRIPT), 'verify', '--bundle', str(self.bundle), *common], capture_output=True, text=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(saved.stdout), json.loads(verified.stdout))
        (self.bundle / 'worker.ps1').write_bytes(b'changed')
        failed = subprocess.run([sys.executable, str(SCRIPT), 'verify', '--bundle', str(self.bundle), *common], capture_output=True, text=True)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stderr)['status'], 'failed')
        self.assertEqual(failed.stdout, '')
        self.assertNotIn(str(self.root), failed.stderr)


if __name__ == '__main__':
    unittest.main()
