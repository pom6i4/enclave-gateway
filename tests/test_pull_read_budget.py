"""Bounded QGA reads must retain progress without replaying a pull part."""
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.control.qga_client import QgaCommandError
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.transports.stream_frames import BLOCK, Decoder, encode_frame
from enclave_gateway.transports.structured import StructuredSshExecutor, StructuredTransport
from test_mcp_transfer import call, engine_at
from test_stream_poll_recovery import FileQga


MIB = 1024 * 1024


class PullReadBudgetTests(unittest.TestCase):
    def fixture(self, root, delay):
        clock = [100.0]
        engine = engine_at(root)
        control = FileQga(root)
        transport = StructuredTransport(control, engine.config.bastion)
        info = dict(revision=3, block_bytes=BLOCK, instance='a'*32, worker_sha256='b'*64)
        evidence = dict(instance_id=info['instance'], loaded_sha256=info['worker_sha256'],
                        chunked_copy_slots_v1=True, stream_upload_v1=True, operator_copy_max_sec=45)
        transport._verify_dispatch = Mock(return_value=evidence)
        transport._stream_descriptor = Mock(return_value=info)
        (root/f"ipc_req_{info['instance']}.bin").touch()
        destination = root/'destination'
        destination.write_bytes(b'prior destination')
        payload = bytes(range(256)) * 4096
        digest = hashlib.sha256()
        for _ in range(128):
            digest.update(payload)
        actions, delayed, offsets = [], [], []

        def append(path, frame, **options):
            position = FileQga.stream_append(control, path, frame, **options)
            envelope = Decoder().feed(frame)[0][2]
            actions.append(envelope)
            body = b''
            if envelope['copy_action'] == 'pull_info':
                output = f'FILE:{128*MIB}:{digest.hexdigest()}'
            else:
                self.assertEqual(envelope['copy_action'], 'pull_part')
                body = payload
                output = 'SHA256:'+hashlib.sha256(body).hexdigest()
            value = dict(tx_id=envelope['tx_id'], exit_code=0, state='completed',
                         stdout_b64=base64.b64encode(output.encode()).decode(), stderr_b64='',
                         worker_instance=info['instance'], worker_sha256=info['worker_sha256'])
            response = control.local(f"ipc_res_{info['instance']}_{position//BLOCK}.bin")
            response.write_bytes(encode_frame(value)+body)
            if envelope.get('copy_offset') == 29*MIB:
                delayed.extend((response, clock[0]+delay))
            return position

        control.stream_append = append
        request = control._request

        def wire(sock, reader, command, arguments=None):
            if command == 'guest-file-open' and delayed and control.local(arguments['path']) == delayed[0]:
                if clock[0] < delayed[1]:
                    raise QgaCommandError(command, {'error': {'class': 'GenericError', 'desc': 'File busy'}})
            if command == 'guest-file-read':
                # A ready MiB takes more than one three-second QGA exchange.
                # Enforce the actual reader deadline at each wire read, rather
                # than replacing the transport with a precomputed result.
                handle = control.handles[arguments['handle']]
                is_delayed = delayed and Path(handle.name) == delayed[0]
                elapsed = .2 if is_delayed else .001
                if clock[0]+elapsed >= reader.deadline:
                    clock[0] = reader.deadline
                    raise TimeoutError('Control channel deadline expired')
                if is_delayed:
                    offsets.append(handle.tell())
                clock[0] += elapsed
            return request(sock, reader, command, arguments)

        control._request = wire
        control.try_read_bytes = Mock(return_value=json.dumps(dict(
            instance_id=info['instance'], worker_sha256=info['worker_sha256'], status='running')).encode())
        hop = StructuredSshExecutor(transport, control, engine.config.bastion)
        engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
        args = dict(direction='pull', local_path=str(destination), node='app01', remote_path='/tmp/file',
                    chunked=True, timeout_sec=1800, tx_id='bounded_pull')
        return clock, engine, control, args, actions, destination, digest.hexdigest(), offsets

    def run_copy(self, fixture):
        clock, engine, control, args, actions, destination, digest, offsets = fixture
        with patch('time.monotonic', side_effect=lambda: clock[0]), \
                patch('time.sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0]+seconds)):
            return call(McpJsonRpcServer(engine), **args)

    def test_delayed_block_30_retains_qga_progress_and_completes_128_mib_once(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(Path(directory), 38)
            clock, engine, control, args, actions, destination, digest, offsets = fixture
            response = self.run_copy(fixture)
            self.assertNotIn('error', response, response)
            result = json.loads(response['result']['content'][0]['text'])
            progress = result['diagnostics']['copy_progress']
            self.assertEqual(progress['blocks_verified'], 128)
            self.assertTrue(progress['destination_committed'])
            self.assertLess(progress['max_step_elapsed_ms'], 45000)
            self.assertEqual(destination.stat().st_size, 128*MIB)
            with destination.open('rb') as stream:
                hasher = hashlib.sha256()
                while data := stream.read(MIB):
                    hasher.update(data)
            self.assertEqual(hasher.hexdigest(), digest)
            self.assertEqual([a['copy_offset'] for a in actions[1:]], list(range(0,128*MIB,MIB)))
            self.assertEqual(len({a['tx_id'] for a in actions}), 129)
            self.assertEqual(control.append_count, 129)
            self.assertEqual(offsets, sorted(set(offsets)))
            self.assertFalse(control.handles)
            destination.unlink()
            fresh = engine_at(Path(directory))
            fresh._resolve_hop_and_jump = Mock(side_effect=AssertionError('No replay'))
            repeated = call(McpJsonRpcServer(fresh), **args)
            self.assertEqual(repeated['result'], response['result'])
            fresh._resolve_hop_and_jump.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(control.append_count, 129)

    def test_block_30_unavailable_beyond_original_deadline_preserves_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = self.fixture(Path(directory), 46)
            clock, engine, control, args, actions, destination, digest, offsets = fixture
            response = self.run_copy(fixture)
            error = response['error']['data']
            self.assertTrue(error['indeterminate'])
            progress = error['diagnostics']['copy_progress']
            self.assertEqual(progress['block_index'], 30)
            self.assertEqual(progress['blocks_verified'], 29)
            self.assertEqual(progress['response_bytes_received'], 0)
            self.assertEqual(progress['response_read_outcome'], 'open_failed')
            self.assertEqual(destination.read_bytes(), b'prior destination')
            self.assertEqual(len(actions), 31)
            fresh = engine_at(Path(directory))
            fresh._resolve_hop_and_jump = Mock(side_effect=AssertionError('No replay'))
            repeated = call(McpJsonRpcServer(fresh), **args)['error']['data']
            self.assertEqual(repeated['code'], 'transaction_indeterminate')
            self.assertEqual(repeated['diagnostics'], error['diagnostics'])
            fresh._resolve_hop_and_jump.assert_not_called()
            self.assertFalse(control.handles)


if __name__ == '__main__':
    unittest.main()
