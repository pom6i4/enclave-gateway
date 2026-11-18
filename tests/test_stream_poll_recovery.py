"""Recover read-side QGA stalls without publishing a stream request twice."""
import base64
from contextlib import contextmanager, nullcontext
import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.config import BastionSpec
from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.operations.context import OperationContext, OperationError, activate
from enclave_gateway.transports.rdp_vfs import RdpVfsTransport
from enclave_gateway.transports.stream_frames import BLOCK, encode_frame


class FileQga(QgaClient):
    """Exercise real QGA file algorithms against local files and wire faults."""
    def __init__(self, root):
        super().__init__(root/'qga.sock')
        self.root=root;self.handles={};self.serial=0;self.calls=[]
        self.append_count=0;self.fill_count=0;self.read_attempts=0
        self.read_faults=[];self.erase_faults=[];self.on_empty=None

    def local(self, path):return self.root/PureWindowsPath(path).name

    @contextmanager
    def _connect_synced(self, timeout_sec=30):
        self.calls.append(('connect',timeout_sec))
        yield None,SimpleNamespace(deadline=time.monotonic()+timeout_sec)

    def _request(self,sock,reader,command,arguments=None):
        self.calls.append((command,arguments))
        if command=='guest-file-open':
            self.serial+=1
            self.handles[self.serial]=self.local(arguments['path']).open(arguments['mode'])
            return self.serial
        handle=self.handles[arguments['handle']]
        if command=='guest-file-read':
            data=handle.read(arguments['count'])
            return {'count':len(data),'buf-b64':base64.b64encode(data).decode(),'eof':not data}
        if command=='guest-file-write':
            data=base64.b64decode(arguments['buf-b64'])
            return {'count':handle.write(data)}
        if command=='guest-file-seek':return {'position':handle.seek(arguments['offset'],arguments['whence'])}
        if command=='guest-file-flush':handle.flush();return {}
        if command=='guest-file-close':handle.close();del self.handles[arguments['handle']];return {}
        raise AssertionError(command)

    def stream_slot_lock(self,*args):return nullcontext()
    def stream_append(self,*args,**kwargs):
        self.append_count+=1
        return super().stream_append(*args,**kwargs)
    def stream_fill_slot(self,*args,**kwargs):
        self.fill_count+=1
        return super().stream_fill_slot(*args,**kwargs)
    def _stream_read_on_connection(self,sock,reader,path,offset,count):
        if PureWindowsPath(path).name.startswith('ipc_res_'):
            self.read_attempts+=1
            if self.read_faults:raise self.read_faults.pop(0)
            if self.on_empty:return self.on_empty()
        return super()._stream_read_on_connection(sock,reader,path,offset,count)
    def _erase_stream_on_connection(self,sock,reader,remaining):
        if self.erase_faults:raise self.erase_faults.pop(0)
        return super()._erase_stream_on_connection(sock,reader,remaining)


class StreamPollRecoveryTests(unittest.TestCase):
    def fixture(self, root, payload=b'fixture-block'):
        info=dict(revision=3,block_bytes=BLOCK,instance='a'*32,worker_sha256='b'*64)
        spec=BastionSpec(execution_profile='structured_only',structured_backend='operator',spool_protocol='stream',worker_policy_sha256='c'*64)
        control=FileQga(root);transport=RdpVfsTransport(control,spec)
        digest=hashlib.sha256(payload).hexdigest()
        envelope=dict(tx_id='tx_block',op='ssh_copy',copy_action='push_part',copy_length=len(payload),sha256=digest,timeout_ms=45000)
        value=dict(tx_id=envelope['tx_id'],exit_code=0,state='completed',stdout_b64=base64.b64encode(('PART:'+digest).encode()).decode(),stderr_b64='',worker_instance=info['instance'],worker_sha256=info['worker_sha256'])
        request=root/('ipc_req_'+info['instance']+'.bin');request.touch()
        upload=root/('ipc_upload_'+info['instance']+'.bin');upload.write_bytes(b'\0')
        response=root/('ipc_res_'+info['instance']+'_0.bin');response.write_bytes(encode_frame(value))
        readiness={'_stream_descriptor':info,'_heartbeat_expires_unix':time.time()+spec.heartbeat_max_age_sec}
        return control,transport,envelope,readiness,request,upload,response

    def dispatch(self, transport, envelope, readiness, payload=b'fixture-block', timeout=45):
        started=time.monotonic()
        return transport._dispatch_stream(envelope,None,started+timeout,started,readiness,attachment=payload)

    def test_push_recovers_read_timeout_and_connection_loss_without_republication(self):
        for error in (TimeoutError('Control channel deadline expired'),ConnectionResetError('lost read')):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as directory:
                control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
                control.read_faults=[error]
                result=self.dispatch(transport,envelope,ready)
                self.assertEqual(result.stdout,'PART:'+envelope['sha256'])
                self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,2))
                self.assertFalse(any(req.read_bytes()) or any(res.read_bytes()) or any(upload.read_bytes()))
                self.assertIn(('connect',3.0),control.calls)
                self.assertFalse(control.handles)

    def test_erasure_disconnect_retries_only_zeroing_and_releases_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            control.erase_faults=[ConnectionResetError('lost zeroing connection')]
            self.assertEqual(self.dispatch(transport,envelope,ready).exit_code,0)
            self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,1))
            self.assertFalse(any(req.read_bytes()) or any(res.read_bytes()) or any(upload.read_bytes()))

    def test_fatal_erasure_failure_preserves_evidence_and_never_reads_reply_again(self):
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            control.erase_faults=[PermissionError('cleanup denied')]
            with self.assertRaises(OperationError) as raised:self.dispatch(transport,envelope,ready)
            self.assertEqual(raised.exception.code,'worker_result_cleanup_failed')
            self.assertTrue(raised.exception.indeterminate)
            self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,1))
            self.assertTrue(any(req.read_bytes()) and any(res.read_bytes()) and any(upload.read_bytes()))

    def test_deadline_and_cancellation_stop_polling_without_republishing(self):
        for cancel in (False,True):
            with self.subTest(cancel=cancel),tempfile.TemporaryDirectory() as directory:
                control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
                clock=[100.0]
                context=OperationContext('fixture','app01','local',101)
                def expire():
                    if cancel:context.cancel()
                    else:clock[0]=102
                    raise TimeoutError('read interrupted')
                control.on_empty=expire
                with patch('time.monotonic',side_effect=lambda:clock[0]),activate(context):
                    with self.assertRaises(OperationError) as raised:self.dispatch(transport,envelope,ready,timeout=1)
                self.assertEqual(raised.exception.code,'cancelled' if cancel else 'deadline_exceeded')
                self.assertTrue(raised.exception.indeterminate)
                self.assertEqual((control.append_count,control.fill_count),(1,1))
                self.assertTrue(any(req.read_bytes()) and any(res.read_bytes()) and any(upload.read_bytes()))

    def test_worker_state_read_timeout_does_not_discard_a_later_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            clock=[100.0];reads=[0]
            original=control._stream_read_on_connection
            def response(sock,reader,path,offset,count):
                if PureWindowsPath(path).name.startswith('ipc_res_') and not reads[0]:
                    reads[0]+=1;clock[0]=102;return b''
                return original(sock,reader,path,offset,count)
            control._stream_read_on_connection=response
            control.try_read_bytes=Mock(side_effect=TimeoutError('state read stalled'))
            with patch('time.monotonic',side_effect=lambda:clock[0]):
                self.assertEqual(self.dispatch(transport,envelope,ready).exit_code,0)
            self.assertEqual(control.try_read_bytes.call_args.kwargs['timeout_sec'],3.0)
            self.assertEqual((control.append_count,control.fill_count),(1,1))

    def test_local_poll_deadline_expires_without_context_and_retains_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            clock=[100.0]
            def expire():clock[0]=102;raise TimeoutError('read timed out')
            control.on_empty=expire
            with patch('time.monotonic',side_effect=lambda:clock[0]),self.assertRaises(OperationError) as raised:
                self.dispatch(transport,envelope,ready,timeout=1)
            self.assertEqual(raised.exception.code,'worker_response_timeout')
            self.assertTrue(raised.exception.indeterminate)
            self.assertEqual((control.append_count,control.fill_count),(1,1))
            self.assertTrue(any(upload.read_bytes()))

    def test_lost_zero_write_ack_retries_remaining_spans_without_revalidation(self):
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            original=control._request;writes=[];lost=[False]
            def request(sock,reader,command,arguments=None):
                path=Path(control.handles[arguments['handle']].name) if arguments and 'handle' in arguments else None
                result=original(sock,reader,command,arguments)
                if command=='guest-file-write' and not any(base64.b64decode(arguments['buf-b64'])):
                    writes.append(path.name)
                    if path==res and not lost[0]:
                        lost[0]=True;raise ConnectionResetError('lost zero write acknowledgement')
                return result
            control._request=request
            self.assertEqual(self.dispatch(transport,envelope,ready).exit_code,0)
            self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,1))
            self.assertEqual(writes.count(req.name),1)
            self.assertEqual(writes.count(res.name),2)
            self.assertFalse(any(req.read_bytes()) or any(res.read_bytes()) or any(upload.read_bytes()))

    def test_legacy_marker_read_timeout_does_not_lose_the_delivery_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            control,transport,envelope,ready,req,upload,res=self.fixture(root)
            from enclave_gateway.transports.stream_frames import Decoder
            value=Decoder().feed(res.read_bytes())[0][2]
            marker=dict(tx_id=envelope['tx_id'],legacy_result=True,worker_instance='a'*32,worker_sha256='b'*64)
            res.write_bytes(encode_frame(marker))
            legacy=root/('res_'+envelope['tx_id']+'.json');legacy.write_text(json.dumps(value))
            control.read_bytes=Mock(side_effect=[TimeoutError('legacy response read stalled'),legacy.read_bytes()])
            self.assertEqual(self.dispatch(transport,envelope,ready).exit_code,0)
            self.assertEqual(control.read_bytes.call_count,2)
            self.assertEqual((control.append_count,control.fill_count),(1,1))
            self.assertFalse(legacy.read_bytes())

    def test_upload_zeroing_recovers_or_reports_cleanup_failure_after_known_part(self):
        for failure in (ConnectionResetError('upload erase disconnected'),PermissionError('upload erase denied')):
            with self.subTest(failure=type(failure).__name__),tempfile.TemporaryDirectory() as directory:
                control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
                original=control._erase_stream_on_connection;calls=[0]
                def erase(sock,reader,remaining):
                    calls[0]+=1
                    if calls[0]==2:raise failure
                    return original(sock,reader,remaining)
                control._erase_stream_on_connection=erase
                if isinstance(failure,ConnectionError):
                    self.assertEqual(self.dispatch(transport,envelope,ready).exit_code,0)
                    self.assertFalse(any(upload.read_bytes()))
                else:
                    with self.assertRaises(OperationError) as raised:self.dispatch(transport,envelope,ready)
                    self.assertEqual(raised.exception.code,'worker_result_cleanup_failed')
                    self.assertTrue(raised.exception.indeterminate)
                    self.assertTrue(any(upload.read_bytes()))
                self.assertFalse(any(req.read_bytes()) or any(res.read_bytes()))
                self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,1))

    def test_binary_download_partial_read_then_timeout_keeps_decoder_and_cursor(self):
        with tempfile.TemporaryDirectory() as directory:
            payload=bytes(range(256))*1024
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory),payload)
            from enclave_gateway.transports.stream_frames import Decoder
            value=Decoder().feed(res.read_bytes())[0][2]
            value['stdout_b64']=base64.b64encode(('SHA256:'+hashlib.sha256(payload).hexdigest()).encode()).decode()
            res.write_bytes(encode_frame(value)+payload)
            envelope['copy_action']='pull_part'
            original=control._stream_read_on_connection;attempts=[0];offsets=[]
            def read(sock,reader,path,offset,count):
                offsets.append(offset);attempts[0]+=1
                if attempts[0]==1:count=1000
                elif attempts[0]==2:raise TimeoutError('partial download poll stalled')
                return original(sock,reader,path,offset,count)
            control._stream_read_on_connection=read
            download=bytearray();started=time.monotonic()
            result=transport._dispatch_stream(envelope,None,started+45,started,ready,download=download)
            self.assertEqual(result.exit_code,0)
            self.assertEqual(download,payload)
            self.assertEqual(offsets,[0,1000,1000])
            self.assertEqual((control.append_count,control.fill_count),(1,0))
            self.assertFalse(any(req.read_bytes()) or any(res.read_bytes()))

    def test_confirmed_cleanup_cannot_extend_the_step_deadline_without_context(self):
        from enclave_gateway.operations.context import budget
        with tempfile.TemporaryDirectory() as directory:
            control,transport,envelope,ready,req,upload,res=self.fixture(Path(directory))
            clock=[100.0]
            def expire(sock,reader,remaining):
                clock[0]=102
                budget(5,'vfs.erase')
                self.fail('Cleanup exceeded the original step deadline')
            control._erase_stream_on_connection=expire
            with patch('time.monotonic',side_effect=lambda:clock[0]),self.assertRaises(OperationError) as raised:
                self.dispatch(transport,envelope,ready,timeout=1)
            self.assertEqual(raised.exception.code,'deadline_exceeded')
            self.assertTrue(raised.exception.indeterminate)
            self.assertEqual((control.append_count,control.fill_count,control.read_attempts),(1,1,1))
            self.assertTrue(any(req.read_bytes()) and any(res.read_bytes()) and any(upload.read_bytes()))
