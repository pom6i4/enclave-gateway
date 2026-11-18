"""Retry only QGA synchronization, before any command can have been dispatched."""
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.control.qga_client import QgaClient
from enclave_gateway.operations.context import OperationError


class QgaSyncRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.peers=[];self.threads=[];self.failures=[];self.commands=[];self.ids=[]

    def tearDown(self):
        for peer in self.peers:peer.close()
        for thread in self.threads:
            thread.join(2)
            self.assertFalse(thread.is_alive(),'QGA wire peer leaked')
        if self.failures:raise self.failures[0]

    def endpoint(self, acknowledge=True, lose_command=False):
        left,right=socket.socketpair();right.settimeout(2)
        self.peers.append(left)
        def serve():
            try:
                with right,right.makefile('rb') as stream:
                    sync=json.loads(stream.readline()[1:]);self.ids.append(sync['arguments']['id'])
                    if acknowledge:
                        right.sendall(b'\xff'+json.dumps({'return':sync['arguments']['id']}).encode()+b'\n')
                    line=stream.readline()
                    if line:
                        command=json.loads(line);self.commands.append(command['execute'])
                        if not lose_command:right.sendall(b'{"return":{}}\n')
            except Exception as error:self.failures.append(error)
        thread=threading.Thread(target=serve,daemon=True);thread.start();self.threads.append(thread)
        return left

    def test_lost_sync_reply_reopens_socket_before_sending_the_command_once(self):
        with tempfile.TemporaryDirectory() as directory:
            client=QgaClient(Path(directory)/'qga.sock');client._SYNC_ATTEMPT_SEC=.15
            first=self.endpoint(acknowledge=False);second=self.endpoint()
            with patch('enclave_gateway.control.local_socket.connect_local',side_effect=[first,second]) as connect:
                with client._connect_synced(1) as (sock,reader):
                    self.assertEqual(client._request(sock,reader,'guest-ping'),{})
            self.assertEqual(connect.call_count,2)
            self.assertEqual(self.commands,['guest-ping'])
            self.assertEqual(len(set(self.ids)),2)
            self.assertEqual(first.fileno(),-1)
            self.assertEqual(second.fileno(),-1)

    def test_lost_dispatch_ack_is_not_a_synchronization_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            client=QgaClient(Path(directory)/'qga.sock')
            endpoint=self.endpoint(lose_command=True)
            with patch('enclave_gateway.control.local_socket.connect_local',return_value=endpoint) as connect:
                with self.assertRaises(ConnectionError):client.exec_guest('fixture.exe',timeout_sec=1)
            self.assertEqual(connect.call_count,1)
            self.assertEqual(self.commands,['guest-exec'])

    def test_missing_or_refused_endpoint_keeps_the_connect_diagnostic(self):
        for error in (FileNotFoundError('endpoint missing'),ConnectionRefusedError('endpoint refused')):
            with self.subTest(error=type(error).__name__),tempfile.TemporaryDirectory() as directory:
                client=QgaClient(Path(directory)/'qga.sock')
                with patch('enclave_gateway.control.local_socket.connect_local',side_effect=error) as connect:
                    with self.assertRaises(OperationError) as raised:
                        with client._connect_synced(1):self.fail('Missing endpoint yielded a connection')
                self.assertEqual(raised.exception.code,'qga_unavailable')
                self.assertEqual(raised.exception.stage,'control.connect')
                self.assertEqual(connect.call_count,1)

    def test_repeated_sync_failures_respect_the_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            client=QgaClient(Path(directory)/'qga.sock');client._SYNC_ATTEMPT_SEC=.1
            def connect(*args):return self.endpoint(acknowledge=False)
            started=time.monotonic()
            with patch('enclave_gateway.control.local_socket.connect_local',side_effect=connect):
                with self.assertRaises(TimeoutError):
                    with client._connect_synced(.35):self.fail('Unacknowledged sync yielded a connection')
            self.assertLess(time.monotonic()-started,2)
            self.assertFalse(self.commands)
            self.assertTrue(all(peer.fileno()==-1 for peer in self.peers))
