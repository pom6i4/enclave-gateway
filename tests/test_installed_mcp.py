"""Reject incomplete or misleading installed-server smoke evidence."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mcp_installed', ROOT/'scripts/qualification/mcp_installed.py')
mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mcp)


class InstalledMcpEvidenceTests(unittest.TestCase):
    def replies(self):
        results = [
            {'serverInfo': {'name': 'enclave-gateway', 'version': '0.4.0.dev0'}, 'protocolVersion': '2025-03-26'},
            {}, {'tools': [{'name': 'node_transfer'}, {'name': 'enclave_capabilities'}]},
            {'isError': False, 'content': [{'text': json.dumps({
                'bastion_execution': {'enabled': False}, 'worker_verification': {'applicable': False}})}]}]
        return [{'jsonrpc': '2.0', 'id': index+1, 'result': value} for index, value in enumerate(results)]

    def test_rejects_stale_version_incomplete_duplicate_and_enabled_worker(self):
        good = self.replies()
        encoded = lambda rows: b'\n'.join(json.dumps(row).encode() for row in rows)
        self.assertEqual(mcp.validate_responses(encoded(good), '0.4.0.dev0')['tools_list_count'], 2)
        stale = self.replies()
        stale[0]['result']['serverInfo']['version'] = '0.3.0'
        remote = self.replies()
        remote[3]['result']['content'][0]['text'] = json.dumps({
            'bastion_execution': {'enabled': True}, 'worker_verification': {'applicable': True}})
        for bad in (good[:-1], good+[good[0]], stale, remote):
            with self.assertRaises(ValueError):
                mcp.validate_responses(encoded(bad), '0.4.0.dev0')


if __name__ == '__main__':
    unittest.main()
