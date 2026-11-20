"""A timed-out periodic challenge must not replay a mutating copy request."""
import base64
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import secrets
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.config import BastionSpec
from enclave_gateway.operations.context import OperationContext, OperationError, activate, budget, limit_deadline
from enclave_gateway.security.attestation import verify
from enclave_gateway.mcp_server.server import McpJsonRpcServer
from enclave_gateway.transports.stream_frames import BLOCK, Decoder, encode_frame
from enclave_gateway.transports.structured import StructuredSshExecutor, StructuredTransport
from test_mcp_transfer import call, engine_at
from test_stream_poll_recovery import FileQga


MIB = 1024*1024


class PeriodicAttestationTests(unittest.TestCase):
    def fixture(self, root, failure):
        clock = [100.0]
        engine = engine_at(root)
        control = FileQga(root)
        transport = StructuredTransport(control, engine.config.bastion)
        engine.rdp_vfs = transport
        transport.attestation_guard = lambda: engine.attest_worker(timeout_sec=budget(10))
        info = dict(revision=3, block_bytes=BLOCK, instance='a'*32, worker_sha256='b'*64)
        transport._stream_descriptor = Mock(return_value=info)
        transport.readiness_guard = lambda: dict(_stream_descriptor=info,
                                                _heartbeat_expires_unix=time.time()+45)
        request = root/f"ipc_req_{info['instance']}.bin"
        request.touch()
        upload = root/f"ipc_upload_{info['instance']}.bin"
        upload.write_bytes(b'\0')
        copies, challenges, stalled = [], [], []
        target_hash = hashlib.sha256()
        first_stalled_nonce = []

        def append(path, frame, **options):
            position = FileQga.stream_append(control, path, frame, **options)
            envelope = Decoder().feed(frame)[0][2]
            response_path = root/f"ipc_res_{info['instance']}_{position//BLOCK}.bin"
            if envelope['op'] == 'attest':
                nonce = envelope['attestation_nonce']
                challenges.append(dict(nonce=nonce, tx_id=envelope['tx_id'],
                                       timeout_ms=envelope['timeout_ms'], parts=len(copies)))
                if len(copies) == 38:
                    if not first_stalled_nonce:
                        first_stalled_nonce.append(nonce)
                        stalled.append(response_path)
                    elif failure == 'always_timeout':
                        stalled.append(response_path)
                evidence = dict(protocol_revision=1, version='0.3.0', nonce=nonce,
                                instance_id=info['instance'], loaded_sha256='b'*64, current_sha256='b'*64,
                                execution_profile='structured_only', execution_model='operator-openssh',
                                sid='S-1-5-21-1000', policy_sha256='a'*64,
                                chunked_copy_slots_v1=True, stream_upload_v1=True, operator_copy_max_sec=45)
                if failure == 'stale_nonce' and first_stalled_nonce and nonce != first_stalled_nonce[0]:
                    evidence['nonce'] = first_stalled_nonce[0]
                output = json.dumps(evidence)
            else:
                self.assertEqual(envelope['op'], 'ssh_copy')
                copies.append(envelope)
                if envelope['copy_action'] == 'push_part':
                    self.assertEqual(envelope['copy_offset'], (len(copies)-1)*MIB)
                    part = upload.read_bytes()[BLOCK:BLOCK+envelope['copy_length']]
                    self.assertEqual(hashlib.sha256(part).hexdigest(), envelope['sha256'])
                    target_hash.update(part)
                    output = 'PART:'+envelope['sha256']
                else:
                    self.assertEqual(envelope['copy_action'], 'push_commit')
                    self.assertEqual(target_hash.hexdigest(), envelope['sha256'])
                    output = 'VERIFIED:'+envelope['sha256']
            value = dict(tx_id=envelope['tx_id'], exit_code=0, state='completed',
                         stdout_b64=base64.b64encode(output.encode()).decode(), stderr_b64='',
                         worker_instance=info['instance'], worker_sha256=info['worker_sha256'])
            response_path.write_bytes(encode_frame(value))
            return position

        control.stream_append = append
        read = control._stream_read_on_connection

        def read_response(sock, reader, path, offset, count):
            if control.local(path) in stalled:
                clock[0] += 10
                raise OperationError('deadline_exceeded', 'control.receive', indeterminate=True)
            return read(sock, reader, path, offset, count)

        control._stream_read_on_connection = read_response
        hop = StructuredSshExecutor(transport, control, engine.config.bastion)
        original_step = hop._copy_step

        def step(*args, **kwargs):
            result = original_step(*args, **kwargs)
            # Host processing between parts ages the real 30-second evidence
            # window. Its first expiry falls after part 38, before part 39.
            if args[4] == 'push_part':
                clock[0] += .8
            return result

        hop._copy_step = step
        engine._resolve_hop_and_jump = Mock(return_value=(hop, None))
        source = root/'source'
        with source.open('wb') as stream:
            for _ in range(128):
                stream.write(b'x'*MIB)
        arguments = dict(direction='push', local_path=str(source), node='app01', remote_path='/tmp/file',
                         chunked=True, timeout_sec=1800, tx_id='periodic_copy')
        return clock, engine, McpJsonRpcServer(engine), arguments, copies, challenges, stalled, control

    def test_timeout_after_38_mib_uses_a_new_nonce_before_resuming_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock, engine, server, args, copies, challenges, stalled, control = self.fixture(root, 'once')
            with patch('time.monotonic', side_effect=lambda: clock[0]), patch('time.time', side_effect=lambda: 1700000000+clock[0]):
                response = call(server, **args)
                self.assertNotIn('error', response, response)
                result = json.loads(response['result']['content'][0]['text'])
                self.assertTrue(result['diagnostics']['copy_progress']['destination_committed'])
                self.assertEqual(result['diagnostics']['copy_progress']['blocks_verified'], 128)
                self.assertEqual(result['diagnostics']['copy_progress']['attestation_retries'], 1)
                self.assertEqual(result['diagnostics']['copy_progress']['attestation_attempts'], len(challenges))
                self.assertLessEqual(result['diagnostics']['copy_progress']['max_step_elapsed_ms'], 45000)
                before = len(copies), len(challenges), control.append_count
                (root/'source').rename(root/'source.backup')
                fresh_engine = engine_at(root)
                fresh_engine._resolve_hop_and_jump = Mock(side_effect=AssertionError('Retained result must not dispatch'))
                repeat = McpJsonRpcServer(fresh_engine).handle_message(dict(
                    jsonrpc='2.0', id=2, method='tools/call', params=dict(name='node_transfer', arguments=args)))
                self.assertEqual(repeat['result'], response['result'])
                fresh_engine._resolve_hop_and_jump.assert_not_called()
                self.assertFalse((root/'source').exists())
                self.assertEqual((len(copies), len(challenges), control.append_count), before)
            self.assertEqual(len(copies), 129)
            self.assertEqual(sum(c['copy_action']=='push_commit' for c in copies), 1)
            self.assertLessEqual(copies[38]['timeout_ms'], 35000)
            self.assertEqual([c['copy_offset'] for c in copies[:-1]], list(range(0,128*MIB,MIB)))
            renewal = [c for c in challenges if c['parts'] == 38]
            self.assertEqual(len(renewal), 2)
            self.assertEqual(len({c['nonce'] for c in challenges}), len(challenges))
            self.assertEqual(len({c['tx_id'] for c in challenges}), len(challenges))
            self.assertTrue(all(0 < c['timeout_ms'] <= 10000 for c in challenges))
            self.assertTrue(any(stalled[0].read_bytes()))
            self.assertFalse(control.handles)

    def test_failed_renewal_never_publishes_part_39_or_commit_and_never_replays(self):
        for failure in ('always_timeout', 'stale_nonce'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clock, engine, server, args, copies, challenges, stalled, control = self.fixture(root, failure)
                with patch('time.monotonic', side_effect=lambda: clock[0]), patch('time.time', side_effect=lambda: 1700000000+clock[0]):
                    error = call(server, **args)['error']['data']
                    self.assertEqual(error['code'], 'deadline_exceeded' if failure == 'always_timeout' else 'agent_attestation_failed')
                    progress = error['diagnostics']['copy_progress']
                    self.assertEqual(progress['blocks_verified'], 38)
                    self.assertEqual(progress['request_publications'], 38)
                    self.assertEqual(progress['block_index'], 39)
                    self.assertFalse(progress['destination_committed'])
                    self.assertEqual(progress['attestation_retries'], 1)
                    before = len(copies), len(challenges), control.append_count
                    fresh_engine = engine_at(root)
                    fresh_engine._resolve_hop_and_jump = Mock(side_effect=AssertionError('Retained failure must not dispatch'))
                    repeated = McpJsonRpcServer(fresh_engine).handle_message(dict(
                        jsonrpc='2.0', id=2, method='tools/call', params=dict(name='node_transfer', arguments=args)))['error']['data']
                    self.assertEqual(repeated['code'], 'transaction_indeterminate' if failure == 'always_timeout' else error['code'])
                    self.assertEqual(repeated['diagnostics'], error['diagnostics'])
                    fresh_engine._resolve_hop_and_jump.assert_not_called()
                    self.assertEqual((len(copies), len(challenges), control.append_count), before)
                self.assertEqual(len(copies), 38)
                self.assertEqual(len([c for c in challenges if c['parts']==38]), 2)
                self.assertTrue(all(c['copy_action']=='push_part' for c in copies))
                self.assertFalse(control.handles)


class AttestationRetryBoundaries(unittest.TestCase):
    def transport(self):
        from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
        spec = BastionSpec(execution_profile='structured_only', structured_backend='operator',
                           spool_protocol='stream', worker_policy_sha256='a'*64)
        return RdpVfsTransport(Mock(), spec)

    def evidence(self, nonce):
        return dict(protocol_revision=1, version='0.3.0', nonce=nonce, instance_id='a'*32,
                    loaded_sha256='b'*64, current_sha256='b'*64, sid='S-1-5-21-1000',
                    execution_profile='structured_only', execution_model='operator-openssh',
                    policy_sha256='a'*64, signature_status='Valid', loaded_signature_status='Valid',
                    loaded_signer='C'*40, signer='C'*40)

    def verify(self, evidence, nonce):
        return verify(evidence, nonce, expected_sha256='b'*64, require_signed=True,
                      trusted_signers=('C'*40,), expected_account='S-1-5-21-1000',
                      expected_execution_profile='structured_only', expected_policy_sha256='a'*64,
                      expected_execution_model='operator-openssh')

    def test_security_failures_after_timeout_are_not_retried_or_cached(self):
        for field, value in (
            ('nonce', '0'*64), ('loaded_sha256', 'c'*64), ('current_sha256', 'c'*64),
            ('sid', 'S-1-5-21-1001'), ('policy_sha256', 'c'*64), ('version', '0.3.1'),
            ('execution_model', 'other'), ('signature_status', 'NotSigned'),
            ('loaded_signature_status', 'NotSigned'), ('signer', 'D'*40), ('loaded_signer', 'D'*40),
        ):
            with self.subTest(field=field):
                clock = [100.0]
                transport = self.transport()
                original = self.verify(self.evidence('1'*64), '1'*64)
                challenges = []

                def guard():
                    nonce = secrets.token_hex(32)
                    challenges.append(nonce)
                    if len(challenges) == 1:
                        clock[0] += 10
                        raise OperationError('deadline_exceeded', 'control.receive')
                    evidence = self.evidence(nonce)
                    evidence[field] = value
                    return self.verify(evidence, nonce)

                transport.attestation_guard = guard
                with patch('time.monotonic', side_effect=lambda: clock[0]):
                    with transport.chunked_copy_session(original):
                        clock[0] += 31
                        with self.assertRaises(OperationError) as raised:
                            transport._verify_dispatch('ssh_copy')
                        self.assertEqual(raised.exception.code, 'agent_attestation_failed')
                        self.assertIs(transport._copy_session.get()['evidence'], original)
                        self.assertLess(transport._copy_session.get()['verified_until'], clock[0])
                self.assertEqual(len(challenges), 2)
                self.assertNotEqual(*challenges)
                self.assertIsNone(transport._verified_worker)

    def test_instance_change_after_timeout_invalidates_the_copy_session(self):
        transport = self.transport()
        clock = [100.0]
        evidence = dict(verified=True, instance_id='a'*32, loaded_sha256='b'*64)
        transport.attestation_guard = Mock(side_effect=[TimeoutError(), {**evidence, 'instance_id': 'c'*32}])
        with patch('time.monotonic', side_effect=lambda: clock[0]), transport.chunked_copy_session(evidence):
            clock[0] += 31
            for _ in range(2):
                with self.assertRaises(OperationError) as raised:
                    transport._verify_dispatch('ssh_copy')
                self.assertEqual(raised.exception.code, 'agent_instance_changed')
        self.assertEqual(transport.attestation_guard.call_count, 2)

    def test_parent_deadline_and_cancellation_prevent_a_second_challenge(self):
        for reason in ('deadline', 'cancel'):
            with self.subTest(reason=reason):
                clock = [100.0]
                transport = self.transport()
                context = OperationContext('copy', 'app01', 'local', 500)
                evidence = dict(verified=True, instance_id='a'*32, loaded_sha256='b'*64)

                def guard():
                    if reason == 'deadline':
                        clock[0] += 45
                    else:
                        context.cancelled.set()
                    raise OperationError('deadline_exceeded', 'control.receive')

                transport.attestation_guard = Mock(side_effect=guard)
                with patch('time.monotonic', side_effect=lambda: clock[0]), activate(context):
                    with transport.chunked_copy_session(evidence):
                        clock[0] += 31
                        with limit_deadline(45), self.assertRaises(OperationError) as raised:
                            transport._verify_dispatch('ssh_copy')
                        self.assertEqual(raised.exception.code, 'cancelled' if reason == 'cancel' else 'deadline_exceeded')
                transport.attestation_guard.assert_called_once()

    def test_initial_and_forced_attestation_keep_one_attempt(self):
        for session in (False, True):
            with self.subTest(session=session):
                transport = self.transport()
                transport.attestation_guard = Mock(side_effect=TimeoutError())
                evidence = dict(verified=True, instance_id='a'*32, loaded_sha256='b'*64)
                scope = transport.chunked_copy_session(evidence) if session else nullcontext()
                with scope, self.assertRaises(TimeoutError):
                    transport._verify_dispatch('ssh_copy', force=True)
                transport.attestation_guard.assert_called_once()


if __name__ == '__main__':
    unittest.main()
