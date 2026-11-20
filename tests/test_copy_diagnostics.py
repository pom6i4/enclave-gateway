"""Observe copy boundaries without extending budgets or replaying dispatch."""
import base64
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.operations.context import OperationContext, activate, copy_diagnostics, measured, update_copy_progress
from enclave_gateway.transports.stream_frames import BLOCK, Decoder, encode_frame
from enclave_gateway.transports.structured import StructuredSshExecutor, StructuredTransport
from enclave_gateway.control.qga_client import ExecResult
from enclave_gateway.operations.context import mark_dispatched
from enclave_gateway.mcp_server.server import McpJsonRpcServer as McpServer
from test_mcp_transfer import engine_at, call
from test_stream_poll_recovery import FileQga


class CopyDiagnosticsTests(unittest.TestCase):
    def fixture(self, root, clock, delay):
        engine = engine_at(root)
        control = FileQga(root)
        transport = StructuredTransport(control, engine.config.bastion)
        info = dict(revision=3, block_bytes=BLOCK, instance='a'*32, worker_sha256='b'*64)
        evidence = dict(instance_id=info['instance'], loaded_sha256=info['worker_sha256'],
                        chunked_copy_slots_v1=True, stream_upload_v1=True, operator_copy_max_sec=45)
        transport._verify_dispatch = Mock(return_value=evidence)
        transport._stream_descriptor = Mock(return_value=info)
        request = root/('ipc_req_'+info['instance']+'.bin')
        request.touch()
        (root/('ipc_upload_'+info['instance']+'.bin')).write_bytes(b'\0')
        original_append = control.stream_append
        actions = []
        def append(path, frame, **options):
            position = original_append(path, frame, **options)
            envelope = Decoder().feed(frame)[0][2]
            actions.append(envelope['copy_action'])
            output = ('PART:' if envelope['copy_action']=='push_part' else 'VERIFIED:')+envelope['sha256']
            value = dict(tx_id=envelope['tx_id'], exit_code=0, state='completed',
                         stdout_b64=base64.b64encode(output.encode()).decode(), stderr_b64='',
                         worker_instance=info['instance'], worker_sha256=info['worker_sha256'])
            (root/f"ipc_res_{info['instance']}_{position//BLOCK}.bin").write_bytes(encode_frame(value))
            return position
        control.stream_append = append
        original_read = control._stream_read_on_connection
        def read(sock, reader, path, offset, count):
            data = original_read(sock, reader, path, offset, count)
            if 'ipc_res_' in path:
                clock[0] += delay
            return data
        control._stream_read_on_connection = read
        hop = StructuredSshExecutor(transport, control, engine.config.bastion)
        engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
        source = root/'source'
        source.write_bytes(b'fixture')
        arguments = dict(direction='push', local_path=str(source), node='app01', remote_path='/tmp/file',
                         chunked=True, timeout_sec=1800, tx_id='observed_copy')
        return engine, control, McpServer(engine), arguments, actions

    def test_qga_latency_beyond_step_limit_is_retained_without_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);clock=[100.0]
            engine, control, server, args, actions = self.fixture(root, clock, 61.7)
            with patch('time.monotonic', side_effect=lambda: clock[0]):
                response = call(server, **args)
                error = response['error']['data']
                self.assertTrue(error['indeterminate'])
                diagnostics = error['diagnostics']
                progress = diagnostics['copy_progress']
                self.assertEqual(progress['control_kind'], 'qga')
                self.assertEqual(progress['block_index'], 1)
                self.assertEqual(progress['offset_bytes'], 0)
                self.assertEqual(progress['step_budget_ms'], 45000)
                self.assertEqual(progress['blocks_verified'], 0)
                self.assertEqual(progress['request_publications'], 1)
                self.assertGreaterEqual(progress['step_elapsed_ms'], 61699)
                self.assertGreaterEqual(diagnostics['timings_ms']['vfs.response_read'], 61699)
                self.assertFalse(progress['destination_committed'])
                retained = engine.transaction_status(args['tx_id'])
                self.assertEqual(retained['state'], 'indeterminate')
                self.assertEqual(retained['error']['diagnostics'], diagnostics)
                repeat = call(server, **args)['error']['data']
                self.assertEqual(repeat['code'], 'transaction_indeterminate')
                self.assertEqual(repeat['diagnostics'], diagnostics)
            self.assertEqual(actions, ['push_part'])
            self.assertEqual((control.append_count, control.fill_count), (1, 1))
            self.assertTrue(any(next(root.glob('ipc_req_*.bin')).read_bytes()))
            self.assertTrue(any(next(root.glob('ipc_res_*.bin')).read_bytes()))
            self.assertFalse(control.handles)

    def test_success_reports_verified_progress_and_same_id_keeps_original_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            clock=[100.0]
            engine, control, server, args, actions = self.fixture(Path(directory), clock, 2.0)
            with patch('time.monotonic', side_effect=lambda: clock[0]):
                response = call(server, **args)
                result = json.loads(response['result']['content'][0]['text'])
                progress = result['diagnostics']['copy_progress']
                self.assertEqual(progress['bytes_verified'], 7)
                self.assertEqual(progress['blocks_verified'], 1)
                self.assertEqual(progress['request_publications'], 2)
                self.assertTrue(progress['destination_committed'])
                self.assertEqual(result['sha256'], hashlib.sha256(b'fixture').hexdigest())
                repeated = call(server, **args)
                self.assertEqual(response, repeated)
            self.assertEqual(actions, ['push_part', 'push_commit'])
            self.assertEqual((control.append_count, control.fill_count), (2, 1))

    def test_observation_does_not_change_error_stage_and_filters_private_fields(self):
        context=OperationContext('fixture','app01','local',200.0)
        context.stage='vfs.response'
        clock=[100.0]
        with patch('time.monotonic', side_effect=lambda: clock[0]), activate(context):
            update_copy_progress(direction='pull', block_index=75, offset_bytes=74*1024*1024,
                                 remote_path='/private/fixture', tx_id='private-id', policy_sha256='a'*64,
                                 command='private command', file_size_bytes=-1)
            with measured('vfs.response_read'):
                clock[0]+=1
            diagnostics = copy_diagnostics()
        self.assertEqual(context.stage, 'vfs.response')
        self.assertEqual(set(diagnostics['copy_progress']), {'direction', 'block_index', 'offset_bytes'})
        self.assertEqual(diagnostics['timings_ms'], {'vfs.response_read': 1000})

    def test_late_pull_does_not_replace_destination_or_replay_the_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);clock=[100.0]
            engine=engine_at(root)
            transport=Mock()
            transport.chunked_copy_session=lambda evidence:nullcontext()
            transport._verify_dispatch.return_value={'chunked_copy_slots_v1':True,'operator_copy_max_sec':45}
            payload=b'new data'
            digest=hashlib.sha256(payload).hexdigest()
            def request(op,timeout,**fields):
                mark_dispatched()
                if fields['copy_action']=='pull_info':
                    return ExecResult(0,f'FILE:{len(payload)}:{digest}','',0)
                fields['download'].extend(payload)
                clock[0]+=61.7
                return ExecResult(0,'SHA256:'+digest,'',61700)
            transport.request.side_effect=request
            hop=StructuredSshExecutor(transport,engine.control,engine.config.bastion)
            engine._resolve_hop_and_jump=Mock(return_value=(hop,None))
            destination=root/'destination';destination.write_bytes(b'keep prior destination')
            args=dict(direction='pull',node='app01',local_path=str(destination),remote_path='/tmp/file',
                      chunked=True,timeout_sec=1800,tx_id='late_pull')
            server=McpServer(engine)
            with patch('time.monotonic',side_effect=lambda:clock[0]):
                error=call(server,**args)['error']['data']
                self.assertTrue(error['indeterminate'])
                progress=error['diagnostics']['copy_progress']
                self.assertEqual(progress['block_index'],1)
                self.assertEqual(progress['bytes_verified'],0)
                self.assertFalse(progress['destination_committed'])
                self.assertEqual(call(server,**args)['error']['data']['code'],'transaction_indeterminate')
            self.assertEqual(destination.read_bytes(),b'keep prior destination')
            self.assertEqual(transport.request.call_count,2)
            self.assertEqual({p.name for p in root.iterdir()},{'destination','state'})

if __name__ == '__main__':
    unittest.main()
