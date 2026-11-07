"""Committed stream framing, no-replay, erasure and real worker integration."""
import base64
import contextlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

from enclave_gateway.config import BastionSpec
from enclave_gateway.control.qga_client import DirectHostControlChannel, QgaClient
from enclave_gateway.operations.context import OperationError
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
from enclave_gateway.transports.stream_frames import Decoder, encode_frame, MAX_BODY

ROOT = Path(__file__).resolve().parents[1]


class StreamFramingTests(unittest.TestCase):
    def test_partial_corrupt_torn_and_erased_frames_resynchronize(self):
        frame = encode_frame({'tx_id': 'tx_valid', 'text': 'кириллица\n\0'})
        decoder = Decoder(21)
        self.assertEqual(decoder.feed(b'\0'*100 + frame[:50]), [])
        values = decoder.feed(frame[50:])
        self.assertEqual(values, [(121, len(frame), {'tx_id': 'tx_valid', 'text': 'кириллица\n\0'})])
        corrupt = frame.replace(b'EGWS1 a', b'EGWS1 b') if frame.startswith(b'EGWS1 a') else frame[:8] + b'x' + frame[9:]
        self.assertEqual(Decoder().feed(corrupt), [])
        self.assertEqual(Decoder().feed(frame[:50]+frame)[0][2]['tx_id'], 'tx_valid')
        decoder = Decoder()
        for _ in range(100):
            self.assertEqual(decoder.feed(b'x'*65536), [])
            self.assertLessEqual(len(decoder.buffer), 5)
        # Correct checksum alone must not admit a different encoding or a
        # deeply nested JSON document that could abort the response observer.
        import hashlib
        for body in ('{"tx_id":"wrong-encoding"}'.encode('utf-16'), ('{"a":'*1200+'0'+'}'*1200).encode()):
            framed=b'EGWS1 '+hashlib.sha256(body).hexdigest().encode()+b' '+base64.b64encode(body)+b'\n'
            self.assertEqual(Decoder().feed(framed+frame)[0][2]['tx_id'],'tx_valid')
        with self.assertRaises(ValueError):
            encode_frame({'text': 'x'*MAX_BODY})

    def test_snapshot_group_uses_one_sync_and_closes_each_handle(self):
        client=QgaClient('/tmp/egw-snapshot.sock')
        @contextlib.contextmanager
        def connection(*args):yield None,None
        client._connect_synced=Mock(side_effect=connection)
        client._request=Mock(side_effect=[1,{'buf-b64':'e30=','count':2,'eof':False},{'buf-b64':'','count':0,'eof':True},{},
                                          2,{'buf-b64':'ew==','count':1,'eof':False},{'buf-b64':'fQ==','count':1,'eof':False},{'buf-b64':'','count':0,'eof':True},{}])
        with client.read_session() as read:
            self.assertEqual(read('descriptor'),b'{}')
            self.assertEqual(read('pulse'),b'{}')
            with self.assertRaisesRegex(ValueError,'read-only'):read('pulse',truncate_after_read=True)
        self.assertEqual(client._connect_synced.call_count,1)
        self.assertEqual([call.args[2] for call in client._request.call_args_list],
                         ['guest-file-open','guest-file-read','guest-file-read','guest-file-close',
                          'guest-file-open','guest-file-read','guest-file-read','guest-file-read','guest-file-close'])

    def test_qga_erases_both_spans_under_one_sync(self):
        client=QgaClient('/tmp/egw-erase.sock')
        @contextlib.contextmanager
        def connection(*args):yield None,None
        client._connect_synced=Mock(side_effect=connection)
        client._request=Mock(side_effect=[17,{}, {'count':3},{},{},18,{'count':5},{},{}])
        client.stream_erase_many([('request',8,3),('response',0,5)])
        self.assertEqual(client._connect_synced.call_count,1)
        self.assertEqual([call.args[2] for call in client._request.call_args_list],
                         ['guest-file-open','guest-file-seek','guest-file-write','guest-file-flush','guest-file-close',
                          'guest-file-open','guest-file-write','guest-file-flush','guest-file-close'])
        writes=[call.args[3] for call in client._request.call_args_list if call.args[2]=='guest-file-write']
        self.assertEqual([base64.b64decode(call['buf-b64']) for call in writes],[bytes(3),bytes(5)])

    def test_validated_read_erases_without_sync_or_validator_replay(self):
        from enclave_gateway.control.qga_client import QgaCommandError
        client=QgaClient('/tmp/egw-commit.sock')
        @contextlib.contextmanager
        def connection(*args):yield None,None
        client._connect_synced=Mock(side_effect=connection)
        client._request=Mock(side_effect=[17,{'buf-b64':'e30=','count':2},{},18,{'count':3},{},{}])
        validator=Mock(return_value=[('response',0,3)])
        self.assertEqual(client.stream_read_committed('response',0,validator),b'{}')
        self.assertEqual(client._connect_synced.call_count,1);validator.assert_called_once_with(b'{}')
        client._request=Mock(side_effect=[17,{'buf-b64':'e30=','count':2},{},QgaCommandError('guest-file-open',{})])
        client.stream_erase_many=Mock(side_effect=QgaCommandError('guest-file-open',{}));validator.reset_mock()
        with self.assertRaises(OperationError) as failure:client.stream_read_committed('response',0,validator)
        self.assertTrue(failure.exception.indeterminate);self.assertEqual(validator.call_count,1)
        self.assertEqual(client.stream_erase_many.call_count,1)

    def test_qga_reads_binary_response_with_one_open_and_sync(self):
        client = QgaClient('/tmp/egw-download.sock')
        first = b'x' * client.CHUNK_SIZE
        @contextlib.contextmanager
        def connection(*args):
            yield None, None
        client._connect_synced = Mock(side_effect=connection)
        client._request = Mock(side_effect=[
            17, {'buf-b64': base64.b64encode(first), 'count': len(first)},
            {'buf-b64': 'AA==', 'count': 1, 'eof': True}, {},
        ])
        validator = Mock(return_value=[])
        self.assertEqual(client.stream_read_committed('response', 0, validator, count=len(first) + 2), first + b'\0')
        client._connect_synced.assert_called_once()
        self.assertEqual([call.args[2] for call in client._request.call_args_list],
                         ['guest-file-open', 'guest-file-read', 'guest-file-read', 'guest-file-close'])
        validator.assert_called_once_with(first + b'\0')

    def test_unacknowledged_upload_slot_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'slot'
            path.write_bytes(b'\0')
            channel = DirectHostControlChannel()
            with channel.stream_slot_lock(str(path), 1):
                channel.stream_fill_slot(str(path), b'first')
            unacknowledged = path.read_bytes()
            with channel.stream_slot_lock(str(path), 1):
                with self.assertRaisesRegex(OperationError, 'unacknowledged block'):
                    channel.stream_fill_slot(str(path), b'second')
            self.assertEqual(path.read_bytes(), unacknowledged)

    def test_file_gate_preserves_fifo_and_removes_timed_out_waiters(self):
        import threading
        import enclave_gateway.control.qga_client as module
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'gate';order=[];threads=[];key=os.path.normcase(os.path.abspath(path))
            def waiter(number):
                with module._file_lock(path,timeout_sec=3):order.append(number)
            with module._file_lock(path):
                for number in range(3):
                    thread=threading.Thread(target=waiter,args=(number,));thread.start();threads.append(thread)
                    deadline=time.monotonic()+2
                    while True:
                        with module._thread_file_gates_guard:count=module._thread_file_gates[key]['users']
                        if count==number+2:break
                        if time.monotonic()>deadline:self.fail('Contender failed to enter gate')
                        time.sleep(.001)
                errors=[]
                def expire():
                    try:
                        with module._file_lock(path,timeout_sec=.02):pass
                    except TimeoutError:errors.append('expired')
                thread=threading.Thread(target=expire);thread.start();thread.join(timeout=1)
                self.assertEqual(errors,['expired'])
            for thread in threads:thread.join(timeout=3);self.assertFalse(thread.is_alive())
            self.assertEqual(order,[0,1,2])
            with module._thread_file_gates_guard:self.assertNotIn(key,module._thread_file_gates)

    def test_short_qga_write_is_not_retried_or_replayed(self):
        with tempfile.TemporaryDirectory() as folder:
            client = QgaClient(Path(folder)/'qga.sock')
            @contextlib.contextmanager
            def connection(*args): yield None, None
            client._connect_synced = connection
            client._request = Mock(side_effect=[17, {'position': 0}, {'count': 2}, {}])
            with self.assertRaisesRegex(OSError, 'indeterminate'):
                client.stream_append('C:\\spool\\ipc.bin', b'frame')
            self.assertEqual([c.args[2] for c in client._request.call_args_list],
                             ['guest-file-open', 'guest-file-seek', 'guest-file-write', 'guest-file-close'])

    def test_direct_producers_keep_frames_and_erase_only_own_ranges(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ipc.bin';path.touch()
            channel = DirectHostControlChannel()
            frames = [encode_frame({'tx_id': str(i)}) for i in range(20)]
            def append(frame): return channel.stream_append(str(path), frame)
            with ThreadPoolExecutor(max_workers=4) as pool:
                offsets = list(pool.map(append, frames))
            self.assertEqual(len(Decoder().feed(path.read_bytes())), 20)
            channel.stream_erase(str(path), offsets[5], len(frames[5]))
            values = Decoder().feed(path.read_bytes())
            self.assertEqual(len(values), 19)
            self.assertNotIn('5', [v[2]['tx_id'] for v in values])


@unittest.skipUnless(os.environ.get('EGW_TEST_POWERSHELL'), 'Real PowerShell fixture opt-in')
class StreamWorkerTests(unittest.TestCase):
    def test_parallel_restart_no_replay_large_delivery_and_secret_erasure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve();spool=root/'spool';spool.mkdir()
            stop=root/'stop';logpath=root/'worker.log'
            # Absolute native paths also work with the Direct controller on Windows.
            class Channel(DirectHostControlChannel):
                def _map_path(self, path): return Path(str(path).replace('\\', os.sep))
            channel=Channel()
            transport=RdpVfsTransport(channel, BastionSpec(appliance_spool_dir=str(spool), bastion_spool_dir=str(spool), spool_protocol='stream'))
            def start():
                stop.unlink(missing_ok=True)
                log=logpath.open('ab')
                proc=subprocess.Popen([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-File',str(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'),'-Mode','Standard','-SpoolDir',str(spool),'-StateRoot',str(root/'state'),'-ParallelStreams','1','-SpoolProtocol','Stream','-StopFile',str(stop)],stdout=log,stderr=log)
                deadline=time.monotonic()+20
                while True:
                    try:
                        state=json.loads((spool/'worker_state.json').read_text(encoding='utf-8-sig'))
                        if state['status']=='running' and state['pid']==proc.pid:break
                    except (OSError,ValueError,KeyError):pass
                    if proc.poll() is not None or time.monotonic()>deadline:
                        proc.kill();proc.wait();log.close();self.fail(logpath.read_text(errors='replace'))
                    time.sleep(.02)
                return proc, log
            def close(proc,log):
                stop.touch()
                try:proc.wait(timeout=10)
                except subprocess.TimeoutExpired:proc.kill();proc.wait();raise
                finally:log.close()
                self.assertEqual(proc.returncode,0,logpath.read_text(errors='replace'))
                for path in spool.glob('ipc_res_*.bin'):self.assertFalse(any(path.read_bytes()))
            proc,log=start()
            try:
                self.assertGreaterEqual(len(list(spool.glob('ipc_res_*.bin'))),4)
                self.assertLessEqual(len(list(spool.glob('ipc_res_*.bin'))),32)
                self.assertEqual(transport.exec_bastion("Write-Output 'physical-ticket'",timeout_sec=8,extra_fields={'__stream_ticket':9999}).stdout,'physical-ticket')
                marker='isolated-stream-secret'
                def call(i):
                    result=transport.exec_bastion("Write-Output '"+marker+str(i)+"'",timeout_sec=8)
                    self.assertEqual(result.exit_code,0,result.stderr)
                    self.assertEqual(result.stdout,marker+str(i))
                with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(call,range(12)))
                for path in spool.glob('ipc_*.bin'):
                    if path.stat().st_size:self.assertFalse(any(path.read_bytes()))
                # A torn frame never executes; the following valid frame still does.
                info=json.loads((spool/'ipc_descriptor.json').read_text())
                request=spool/('ipc_req_'+info['instance']+'.bin')
                channel.stream_append(str(request),b'EGWS1 dead partial')
                self.assertEqual(transport.exec_bastion("Write-Output 'after-torn'",timeout_sec=8).stdout,'after-torn')
                result=transport.exec_bastion("Write-Output ('z' * 800000)",timeout_sec=8)
                self.assertEqual(result.stdout,'z'*800000)
                self.assertEqual(result.exit_code,0)
                # Fill an entire dispatcher batch behind one occupied slot.
                # Cancellation must bypass it instead of waiting for its deadline.
                active=root/'cancellable.started'
                script="[IO.File]::WriteAllText('"+str(active).replace("'","''")+"','started');Start-Sleep -Seconds 8"
                cancel_envelope={'tx_id':'tx_cancel','op':'exec','timeout_ms':10000,'payload_b64':base64.b64encode(script.encode()).decode()}
                with ThreadPoolExecutor(max_workers=33) as pool:
                    running=pool.submit(transport._dispatch_envelope,cancel_envelope,timeout_sec=10)
                    deadline=time.monotonic()+3
                    while not active.exists():
                        if time.monotonic()>deadline:self.fail('Owned cancellable command did not start')
                        time.sleep(.005)
                    waiting=[pool.submit(transport.exec_bastion,"Write-Output 'queued'",timeout_sec=10) for _ in range(32)]
                    deadline=time.monotonic()+3
                    while len([v for _,_,v in Decoder().feed(request.read_bytes()) if v.get('op')=='exec'])<33:
                        if time.monotonic()>deadline:self.fail('Owned queue did not fill')
                        time.sleep(.005)
                    transport.request_cancel('tx_cancel')
                    self.assertEqual(running.result(timeout=2).exit_code,125)
                    for future in waiting:self.assertEqual(future.result(timeout=5).stdout,'queued')
                # Deliberately reuse an id; journal survives a worker restart.
                envelope={'tx_id':'tx_replay','op':'exec','timeout_ms':8000,'payload_b64':base64.b64encode(b"Write-Output 'once'").decode()}
                self.assertEqual(transport._dispatch_envelope(envelope,timeout_sec=8).stdout,'once')
            finally:close(proc,log)
            proc,log=start()
            try:
                result=transport._dispatch_envelope(envelope,timeout_sec=8)
                self.assertEqual(result.exit_code,125)
                self.assertIn('Existing transaction',result.stderr)
            finally:close(proc,log)


    def test_delivery_failure_keeps_completed_journal_and_never_reports_execution_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();spool=root/'spool';spool.mkdir();stop=root/'stop';effect=root/'effect'
            (spool/'res_tx_fault.json.tmp').mkdir()  # Actual publication failure, after execution.
            class Channel(DirectHostControlChannel):
                def _map_path(self,path):return Path(str(path).replace('\\',os.sep))
            transport=RdpVfsTransport(Channel(),BastionSpec(appliance_spool_dir=str(spool),spool_protocol='stream'))
            with (root/'worker.log').open('ab') as log:
                proc=subprocess.Popen([os.environ['EGW_TEST_POWERSHELL'],'-NoProfile','-NonInteractive','-File',str(ROOT/'src/enclave_gateway/agents/bastion_worker.ps1'),'-Mode','Standard','-SpoolDir',str(spool),'-StateRoot',str(root/'state'),'-SpoolProtocol','Stream','-StopFile',str(stop)],stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+20
                    while not (spool/'worker_state.json').exists():
                        if proc.poll() is not None or time.monotonic()>deadline:self.fail((root/'worker.log').read_text(errors='replace'))
                        time.sleep(.02)
                    script="[IO.File]::WriteAllText('"+str(effect).replace("'","''")+"','once');Write-Output ('z' * 800000)"
                    envelope={'tx_id':'tx_fault','op':'exec','timeout_ms':6000,'payload_b64':base64.b64encode(script.encode()).decode()}
                    with self.assertRaises(OperationError) as error:
                        transport._dispatch_envelope(envelope,timeout_sec=6)
                    self.assertTrue(error.exception.indeterminate)
                    self.assertEqual(effect.read_text(),'once')
                    binding=json.loads((spool/'worker_storage.json').read_text())
                    record=json.loads((root/'state'/binding['storage_id']/'tx_fault.json').read_text())
                    self.assertEqual(record['state'],'completed')
                    proc.wait(timeout=5)
                    self.assertNotEqual(proc.returncode,0)
                    state=json.loads((spool/'worker_state.json').read_text())
                    self.assertEqual(state['status'],'stopped')
                    self.assertIn('publication failed',state['stream_error'])
                finally:
                    stop.touch()
                    if proc.poll() is None:proc.kill();proc.wait(timeout=5)


class StreamDispatchFailureTests(unittest.TestCase):
    def test_concurrent_readiness_shares_only_inflight_unexpired_snapshot(self):
        import threading
        joined=threading.Event();followers=set();barrier=threading.Barrier(4)
        class ObservedCondition(threading.Condition):
            def wait(self,timeout=None):
                followers.add(threading.get_ident())
                if len(followers)==3:joined.set()
                return super().wait(timeout)
        transport=RdpVfsTransport(Mock(),BastionSpec());transport._ready_condition=ObservedCondition();calls=[]
        def guard():
            calls.append(1)
            self.assertTrue(joined.wait(2))
            return {'_heartbeat_expires_unix':time.time()+10}
        def check():barrier.wait(timeout=2);transport._check_readiness(guard)
        with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda _:check(),range(4)))
        self.assertEqual(len(calls),1)
        transport._check_readiness(guard);transport._check_readiness(guard)
        self.assertEqual(len(calls),3)  # No cache for later requests.
        # A completed failed or expired wave cannot authorize a waiting caller.
        transport._ready_wave={'done':True,'expires':time.time()+10}
        with self.assertRaises(PermissionError):transport._check_readiness(lambda:(_ for _ in ()).throw(PermissionError('unavailable')))

    def test_fresh_readiness_descriptor_is_reused_but_attestation_is_enforced(self):
        info={'revision':3,'block_bytes':4096,'instance':'a'*32,'worker_sha256':'b'*64}
        control=Mock();control.try_read_bytes.return_value=json.dumps(info).encode();control.stream_append.return_value=0
        value={'tx_id':'tx_ready','exit_code':0,'stdout_b64':'','stderr_b64':'','worker_instance':info['instance'],'worker_sha256':info['worker_sha256']}
        control.stream_read.return_value=encode_frame(value)
        transport=RdpVfsTransport(control,BastionSpec(spool_protocol='stream'))
        state={'_heartbeat_expires_unix':time.time()+10,'_stream_descriptor':info}
        transport.readiness_guard=lambda:state
        envelope={'tx_id':'tx_ready','op':'exec','timeout_ms':5000,'payload_b64':''}
        self.assertEqual(transport._dispatch_envelope(envelope,timeout_sec=5).exit_code,0)
        control.try_read_bytes.assert_not_called()
        with patch.object(transport,'_verify_dispatch',return_value={'instance_id':'c'*32,'loaded_sha256':'b'*64}):
            with self.assertRaisesRegex(ValueError,'attested worker'):transport._dispatch_envelope(envelope,timeout_sec=5)
        self.assertEqual(control.stream_append.call_count,1)
        state['_heartbeat_expires_unix']=time.time()-1
        self.assertEqual(transport._dispatch_envelope(envelope,timeout_sec=5).exit_code,0)
        self.assertEqual(control.try_read_bytes.call_count,1)

    def test_valid_stderr_prefix_is_erased_but_malformed_frame_is_retained(self):
        info={'revision':3,'block_bytes':4096,'instance':'a'*32,'worker_sha256':'b'*64}
        control=Mock();control.try_read_bytes.return_value=json.dumps(info).encode();control.stream_append.return_value=0
        message='Malformed BastionWorker response: valid command stderr'
        value={'tx_id':'tx_stderr','exit_code':7,'state':'failed','stdout_b64':'','stderr_b64':base64.b64encode(message.encode()).decode(),'worker_instance':info['instance'],'worker_sha256':info['worker_sha256']}
        control.stream_read.return_value=encode_frame(value)
        transport=RdpVfsTransport(control,BastionSpec(spool_protocol='stream'))
        envelope={'tx_id':'tx_stderr','op':'exec','timeout_ms':5000,'payload_b64':''}
        result=transport._dispatch_envelope(envelope,timeout_sec=5)
        self.assertEqual((result.exit_code,result.stderr),(7,message));self.assertEqual(control.stream_erase.call_count,2)
        control.stream_read.return_value=encode_frame({**value,'exit_code':True})
        with self.assertRaises(OperationError) as failure:transport._dispatch_envelope(envelope,timeout_sec=5)
        self.assertTrue(failure.exception.indeterminate);self.assertEqual(control.stream_erase.call_count,2)

    def test_wrong_attested_instance_and_ambiguous_write_never_use_files(self):
        from enclave_gateway.transports.stream_frames import descriptor
        info={'revision':3,'block_bytes':4096,'instance':'a'*32,'worker_sha256':'b'*64}
        control=Mock()
        control.try_read_bytes.return_value=json.dumps(info).encode()
        control.stream_append.side_effect=ConnectionResetError('ack lost')
        transport=RdpVfsTransport(control,BastionSpec(spool_protocol='stream'))
        with patch.object(transport,'_verify_dispatch',return_value={'instance_id':'c'*32,'loaded_sha256':'b'*64}):
            with self.assertRaisesRegex(ValueError,'attested worker'):
                transport.exec_bastion('write')
        control.stream_append.assert_not_called()
        with self.assertRaises(ConnectionResetError):
            transport.exec_bastion('write')
        self.assertEqual(control.stream_append.call_count,1)
        control.publish_bytes.assert_not_called()
        control.exec_powershell.assert_not_called()
        for raw in (b'[]',b'{}',json.dumps({**info,'instance':'../x'}).encode()):
            with self.assertRaises(ValueError):descriptor(raw)

    def test_fixed_gate_keeps_single_slow_and_failed_samples(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('latency_gate',ROOT/'scripts/qualification/latency_gate.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        rows=[{'ok':True,'elapsed_ms':400} for _ in range(30)]
        self.assertEqual(module.qualify({'cohorts':{'probe':rows}})['status'],'passed')
        for bad in ({'ok':True,'elapsed_ms':800.001},{'ok':False,'elapsed_ms':1},{'ok':True,'elapsed_ms':float('nan')},{'ok':True,'elapsed_ms':True}):
            result=module.qualify({'cohorts':{'probe':rows+[bad]}})
            self.assertEqual(result['status'],'failed');self.assertEqual(result['cohorts']['probe']['failed_indices'],[30])
        self.assertEqual(module.qualify({'cohorts':{'probe':rows[:29]}})['status'],'failed')

    def test_worker_protocol_mismatch_fails_before_publication(self):
        import datetime
        from enclave_gateway.worker_channel import require_running_worker
        control=Mock(supports_direct_spool_ipc=True)
        control.try_read_bytes.return_value=json.dumps({'status':'running','last_heartbeat_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'spool_protocol':'files'}).encode()
        with self.assertRaises(OperationError) as error:
            require_running_worker(control,BastionSpec(spool_protocol='stream'))
        self.assertEqual(error.exception.code,'worker_protocol_mismatch')
        control.publish_bytes.assert_not_called()

    def test_capacity_reserves_control_without_resetting_endpoints(self):
        from enclave_gateway.transports.stream_frames import MAX_STREAM, CONTROL_RESERVE
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'request.bin'
            with path.open('wb') as stream:stream.truncate(MAX_STREAM-CONTROL_RESERVE)
            channel=DirectHostControlChannel()
            with self.assertRaisesRegex(ValueError,'capacity'):
                channel.stream_append(str(path),encode_frame({'op':'exec'}),limit=MAX_STREAM-CONTROL_RESERVE)
            control=encode_frame({'op':'stop'})
            position=channel.stream_append(str(path),control)
            self.assertEqual(position,MAX_STREAM-CONTROL_RESERVE)
            self.assertEqual(Decoder(position).feed(channel.stream_read(str(path),position))[0][2],{'op':'stop'})
            self.assertEqual(path.stat().st_size,position+4096)
            with path.open('r+b') as stream:stream.truncate(MAX_STREAM-1)
            with self.assertRaisesRegex(ValueError,'capacity'):
                channel.stream_append(str(path),control)
            self.assertEqual(path.stat().st_size,MAX_STREAM-1)


    def test_qga_read_open_collision_retries_without_republishing(self):
        from enclave_gateway.control.qga_client import QgaCommandError
        info={'revision':3,'block_bytes':4096,'instance':'a'*32,'worker_sha256':'b'*64}
        control=Mock();control.try_read_bytes.return_value=json.dumps(info).encode();control.stream_append.return_value=0
        value={'tx_id':'tx_once','exit_code':0,'state':'completed','stdout_b64':base64.b64encode(b'once').decode(),'stderr_b64':'','worker_instance':info['instance'],'worker_sha256':info['worker_sha256']}
        control.stream_read.side_effect=[QgaCommandError('guest-file-open',{'error':{'class':'GenericError'}}),encode_frame(value)]
        transport=RdpVfsTransport(control,BastionSpec(spool_protocol='stream'))
        envelope={'tx_id':'tx_once','op':'exec','timeout_ms':5000,'payload_b64':base64.b64encode(b'Write-Output once').decode()}
        self.assertEqual(transport._dispatch_envelope(envelope,timeout_sec=5).stdout,'once')
        self.assertEqual(control.stream_append.call_count,1);self.assertEqual(control.stream_read.call_count,2);control.publish_bytes.assert_not_called()
        control.stream_read.side_effect=QgaCommandError('guest-file-read',{'error':{'class':'GenericError'}})
        with self.assertRaises(QgaCommandError):transport._dispatch_envelope({**envelope,'tx_id':'tx_read_fault'},timeout_sec=5)
        self.assertEqual(control.stream_append.call_count,2);control.publish_bytes.assert_not_called()

    def test_alternating_heartbeats_reject_foreign_instance_and_prefer_stop(self):
        import datetime
        from enclave_gateway.worker_channel import stream_worker_state,require_running_worker
        from enclave_gateway.control.qga_client import QgaCommandError
        info={'revision':3,'block_bytes':4096,'instance':'a'*32,'worker_sha256':'b'*64}
        now=datetime.datetime.now(datetime.timezone.utc).isoformat()
        running={'instance_id':info['instance'],'worker_sha256':info['worker_sha256'],'spool_protocol':'stream','status':'running','last_heartbeat_utc':now}
        slots={'a':QgaCommandError('guest-file-open',{'error':{'class':'GenericError'}}),'b':running}
        class Control:
            supports_direct_spool_ipc=True
            def try_read_bytes(self,path,**kwargs):
                if path.endswith('ipc_descriptor.json'):return json.dumps(info).encode()
                slot=path.rsplit('_',1)[-1].split('.')[0]
                value=slots[slot]
                if isinstance(value,Exception):raise value
                return json.dumps(value).encode()
        control=Control();spec=BastionSpec(spool_protocol='stream')
        require_running_worker(control,spec)
        slots['a']={**running,'status':'stopped'}
        self.assertEqual(stream_worker_state(control,spec)['status'],'stopped')
        with self.assertRaises(OperationError):require_running_worker(control,spec)
        slots['b']={**running,'instance_id':'c'*32}
        self.assertEqual(stream_worker_state(control,spec)['status'],'stopped')
        slots['a']={**running,'last_heartbeat_utc':1}
        self.assertEqual(stream_worker_state(control,spec),{})
        with self.assertRaises(OperationError):require_running_worker(control,spec)
