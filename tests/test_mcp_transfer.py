"""MCP copy routing, authorization and durable transaction boundaries."""
import hashlib
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock

from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.operations.context import mark_dispatched, current
from enclave_gateway.security.policy import AccessPolicy, Grant
from enclave_gateway.transports.structured import StructuredSshExecutor


def call(server, **arguments):
    return server.handle_message({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                 'params': {'name': 'node_transfer', 'arguments': arguments}})


def engine_at(root):
    config = EnclaveConfig.from_dict({'appliance': {'hypervisor': 'direct'},
        'bastion': {'execution_profile': 'structured_only', 'structured_backend': 'operator', 'spool_protocol': 'stream',
                    'worker_policy_sha256': 'a'*64},
        'security': {'mode': 'standard', 'require_signed_agents': False, 'enforce_worker_attestation': True,
                     'worker_sha256': 'b'*64, 'worker_account': 'S-1-5-21-1000'},
        'targets': {'app01': {'host': '10.0.20.11', 'user': 'fixture'}}})
    return EnclaveEngine(config=config, state_dir=Path(root)/'state')


class McpTransferTests(unittest.TestCase):
    def test_invalid_options_fail_before_dispatch(self):
        with TemporaryDirectory() as root:
            engine = engine_at(root)
            engine.transfer_file = Mock()
            engine.transfer_file_chunked = Mock()
            server = McpJsonRpcServer(engine)
            arguments = dict(direction='push', node='app01', local_path='input', remote_path='/tmp/file')
            for extra in ({'chunked': 'true'}, {'timeout_sec': 0}, {'timeout_sec': -1},
                          {'timeout_sec': True}, {'timeout_sec': float('nan')},
                          {'timeout_sec': float('inf')}, {'timeout_sec': 86401}, {'timeout_sec': 10**400}):
                with self.subTest(extra=extra):
                    self.assertEqual(call(server, **arguments, **extra)['error']['code'], -32602)
            engine.transfer_file.assert_not_called()
            engine.transfer_file_chunked.assert_not_called()

    def test_default_and_chunked_dispatch_preserve_explicit_budget(self):
        with TemporaryDirectory() as root:
            engine = engine_at(root)
            engine.transfer_file = Mock(return_value={'sha256': 'a'*64})
            engine.transfer_file_chunked = Mock(return_value={'sha256': 'b'*64})
            server = McpJsonRpcServer(engine)
            arguments = dict(direction='pull', node='app01', local_path='output', remote_path='/tmp/file', tx_id='copy')
            self.assertFalse(call(server, **arguments)['result']['isError'])
            engine.transfer_file.assert_called_once_with('pull', 'output', 'app01', '/tmp/file',
                as_root=False, timeout_sec=900.0, use_delta=True, tx_id='copy', actor='mcp')
            self.assertFalse(call(server, **arguments, chunked=True, timeout_sec=1800)['result']['isError'])
            engine.transfer_file_chunked.assert_called_once_with('pull', 'output', 'app01', '/tmp/file',
                as_root=False, timeout_sec=1800.0, tx_id='copy', actor='mcp')
            self.assertEqual(engine.transfer_file.call_count, 1)

    def test_chunked_copy_keeps_readonly_and_path_grants(self):
        with TemporaryDirectory() as root:
            engine = engine_at(root)
            engine.transfer_file_chunked = Mock()
            arguments = dict(direction='push', node='app01', local_path=str(Path(root)/'input'),
                             remote_path='/srv/allowed/file', chunked=True)
            response = call(McpJsonRpcServer(engine, read_only=True), **arguments)
            self.assertTrue(response['result']['isError'])
            grant = Grant('local', ('node_transfer',), nodes=('app01',),
                          read_roots={'app01': ['/srv/allowed']}, write_roots={'app01': ['/srv/allowed']},
                          local_read_roots=[root], local_write_roots=[root])
            server = McpJsonRpcServer(engine, policy=AccessPolicy({'local': grant}))
            denied = [dict(arguments, remote_path='/srv/secret/file'),
                      dict(arguments, local_path=str(Path(root).parent/'outside')),
                      dict(arguments, node='@bastion'), dict(arguments, as_root=True)]
            for args in denied:
                self.assertEqual(call(server, **args)['error']['code'], -32003)
            engine.transfer_file_chunked.assert_not_called()

    def test_missing_attested_capability_never_falls_back(self):
        with TemporaryDirectory() as root:
            engine = engine_at(root)
            transport = Mock()
            transport._verify_dispatch.return_value = {'chunked_copy_slots_v1': False}
            hop = StructuredSshExecutor(transport, engine.control, engine.config.bastion)
            engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
            engine.transfer_file = Mock()
            response = call(McpJsonRpcServer(engine), direction='push', node='app01',
                            local_path=str(Path(root)/'input'), remote_path='/tmp/file', chunked=True)
            self.assertEqual(response['error']['data']['code'], 'chunked_copy_unavailable')
            transport.request.assert_not_called()
            engine.transfer_file.assert_not_called()

    def test_128_mib_wrapper_round_trip_and_repeated_id_return_retained_result(self):
        # Local file-copy backend substitute: this exercises MCP/engine/journal,
        # not a Windows worker, RDP channel or the real operator wire protocol.
        with TemporaryDirectory() as root:
            root = Path(root)
            source, remote, received = (root/name for name in ('input', 'remote', 'received'))
            with source.open('wb') as stream:
                block = bytes(range(256))*4096
                for _ in range(128):
                    stream.write(block)
            expected = hashlib.sha256(block*128).hexdigest()
            engine = engine_at(root)
            hop = StructuredSshExecutor(Mock(), engine.control, engine.config.bastion)
            calls = []
            def copy(direction, target, local, remote_path, **options):
                calls.append(direction)
                self.assertGreater(current().remaining(), 1700)
                mark_dispatched()
                shutil.copyfile(local if direction == 'push' else remote,
                                remote if direction == 'push' else local)
                return expected
            hop.copy_chunked = copy
            engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
            server = McpJsonRpcServer(engine)
            for direction, local in (('push', source), ('pull', received)):
                args = dict(direction=direction, local_path=str(local), node='app01',
                            remote_path='/tmp/file', chunked=True, timeout_sec=1800, tx_id='copy_'+direction)
                first = call(server, **args)
                self.assertEqual(json.loads(first['result']['content'][0]['text'])['sha256'], expected)
                second = call(server, **args)
                self.assertEqual(first, second)
            self.assertEqual(calls, ['push', 'pull'])
            self.assertEqual(received.stat().st_size, 128*1024*1024)
            with received.open('rb') as stream:
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024*1024), b''):
                    digest.update(block)
            self.assertEqual(digest.hexdigest(), expected)

    def test_lost_reply_is_indeterminate_and_same_id_cannot_repeat_copy(self):
        with TemporaryDirectory() as root:
            engine = engine_at(root)
            hop = StructuredSshExecutor(Mock(), engine.control, engine.config.bastion)
            def lost_reply(*args, **kwargs):
                mark_dispatched()
                raise TimeoutError('Fixture lost commit reply')
            hop.copy_chunked = Mock(side_effect=lost_reply)
            engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
            server = McpJsonRpcServer(engine)
            args = dict(direction='push', local_path=str(Path(root)/'input'), node='app01',
                        remote_path='/tmp/file', chunked=True, timeout_sec=1800, tx_id='lost_reply')
            for _ in range(2):
                response = call(server, **args)
                self.assertTrue(response['error']['data']['indeterminate'])
            self.assertEqual(engine.transaction_status('lost_reply')['state'], 'indeterminate')
            hop.copy_chunked.assert_called_once()
            response = call(server, **dict(args, chunked=False))
            self.assertEqual(response['error']['data']['code'], 'transaction_conflict')


if __name__ == '__main__':
    unittest.main()
