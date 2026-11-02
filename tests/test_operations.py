"""Durable operation, deadline and authenticated authorization regressions."""
from __future__ import annotations

import io
import json
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.control.qga_client import DirectHostControlChannel, ExecResult
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer, McpHttpServer
from enclave_gateway.operations.context import OperationContext, OperationError, activate, bind_context, budget, checkpoint, identity, mark_dispatched
from enclave_gateway.operations.journal import TransactionJournal
from enclave_gateway.security.policy import AccessPolicy, Grant, ScopedMuxTransport, below, grant_scope
from enclave_gateway.security.secrets import SecretVault


def engine_at(root, control=None):
    return EnclaveEngine(EnclaveConfig.from_dict({"appliance": {"hypervisor": "direct"}, "targets": {
        "app01": {"host": "10.0.20.11", "user": "lab"}}}),
        vault=SecretVault(env_file=Path(root)/"absent.env"), recorder=FlightRecorder(Path(root)/"audit.jsonl"),
        control_override=control or DirectHostControlChannel(Path(root)))


def call(server, tool, args, principal="local", request_id=1):
    return server.handle_message({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                                 "params": {"name": tool, "arguments": args}}, principal=principal)


class OperationTests(unittest.TestCase):
    def test_corrupt_worker_reply_is_indeterminate_and_never_republished(self):
        with TemporaryDirectory() as root:
            control=Mock();control.supports_direct_spool_ipc=True
            def corrupt(path,**_):
                if path.endswith('worker_state.json'):
                    import datetime
                    return json.dumps({'status':'running','last_heartbeat_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}).encode()
                tx=path.replace('\\','/').rsplit('/',1)[-1][4:-5]
                return json.dumps({'tx_id':tx,'exit_code':'invalid','stdout_b64':'','stderr_b64':''}).encode()
            control.try_read_bytes.side_effect=corrupt
            engine=engine_at(root,control)
            with self.assertRaises(OperationError) as caught:
                engine.exec_node('@bastion',"Write-Output 'fixture'",tx_id='corrupt_reply')
            self.assertTrue(caught.exception.indeterminate)
            self.assertEqual(engine.transaction_status('corrupt_reply')['state'],'indeterminate')
            published=control.publish_bytes.call_count
            with self.assertRaises(OperationError):
                engine.exec_node('@bastion',"Write-Output 'fixture'",tx_id='corrupt_reply')
            self.assertEqual(control.publish_bytes.call_count,published)

    def test_restart_returns_retained_result_and_does_not_reexecute(self):
        with TemporaryDirectory() as root:
            control=Mock()
            control.exec_powershell.return_value=ExecResult(0,"once","",1)
            first=engine_at(root,control)
            result=first.exec_node("@appliance","echo once",tx_id="stable")
            second=engine_at(root,control).exec_node("@appliance","echo once",tx_id="stable")
            self.assertEqual((result.stdout,second.stdout,second.tx_id),("once","once","stable"))
            self.assertEqual(control.exec_powershell.call_count,1)
            with self.assertRaises(OperationError) as conflict:
                first.exec_node("@appliance","echo different",tx_id="stable")
            self.assertEqual(conflict.exception.code,"transaction_conflict")
            with identity("another"):
                self.assertIsNone(first.journal.get("stable","another"))
                with self.assertRaises(OperationError):
                    first.exec_node("@appliance","echo once",tx_id="stable")
            if os.name != "nt": self.assertEqual(first.journal.path.stat().st_mode & 0o777,0o600)

    def test_result_storage_failure_retains_identity_and_blocks_replay(self):
        with TemporaryDirectory() as root:
            engine=engine_at(root,Mock());engine.control.exec_powershell.return_value=ExecResult(0,'observed','',1)
            original=engine.journal.update
            def fail_completed(tx,owner,state,**values):
                if state in ('completed','indeterminate'):raise OSError('fixture ENOSPC')
                return original(tx,owner,state,**values)
            engine.journal.update=fail_completed
            with self.assertRaises(OSError) as caught:engine.exec_node('@appliance','printf observed',tx_id='storage',timeout_sec=5)
            self.assertEqual(caught.exception.operation_error.code,'journal_persistence_failed')
            self.assertTrue(caught.exception.operation_error.indeterminate)
            engine.journal.update=original
            with self.assertRaises(OperationError):engine.exec_node('@appliance','printf observed',tx_id='storage',timeout_sec=5)
            self.assertEqual(engine.control.exec_powershell.call_count,1)

    def test_late_cancellation_preserves_obtained_result(self):
        with TemporaryDirectory() as root:
            from enclave_gateway.operations.context import current
            control=Mock()
            def complete(*args,**kwargs):
                mark_dispatched()
                return ExecResult(0,'retained-result','',1)
            control.exec_powershell.side_effect=complete
            engine=engine_at(root,control)
            original=engine.recorder.record
            def acknowledge_then_cancel(*args,**kwargs):
                result=original(*args,**kwargs)
                current().cancel()
                return result
            engine.recorder.record=acknowledge_then_cancel
            with self.assertRaises(OperationError) as caught:
                engine.exec_node('@appliance','fixture',tx_id='late')
            self.assertTrue(caught.exception.as_dict()['known_outcome'])
            self.assertFalse(caught.exception.indeterminate)
            row=engine.transaction_status('late')
            self.assertEqual(row['state'],'completed')
            self.assertEqual(row['result']['value']['stdout'],'retained-result')
            self.assertEqual(engine.exec_node('@appliance','fixture',tx_id='late').stdout,'retained-result')
            self.assertEqual(control.exec_powershell.call_count,1)

    def test_concurrent_duplicate_is_reserved_before_dispatch(self):
        with TemporaryDirectory() as root:
            entered,release=threading.Event(),threading.Event()
            control=Mock()
            def execute(*args,**kwargs):
                entered.set(); release.wait(3)
                return ExecResult(0,"once","",1)
            control.exec_powershell.side_effect=execute
            engine=engine_at(root,control)
            with ThreadPoolExecutor(max_workers=2) as pool:
                job=pool.submit(engine.exec_node,"@appliance","echo once",tx_id="concurrent")
                self.assertTrue(entered.wait(2))
                try:
                    with self.assertRaises(OperationError) as caught:
                        engine.exec_node("@appliance","echo once",tx_id="concurrent")
                    self.assertEqual(caught.exception.code,"transaction_in_progress")
                finally: release.set()
                self.assertEqual(job.result().stdout,"once")
            self.assertEqual(control.exec_powershell.call_count,1)

    def test_cli_reports_structured_operation_failure(self):
        from enclave_gateway.cli import main
        error=OperationError("deadline_exceeded","fixture",tx_id="cli_tx",indeterminate=True)
        with patch("enclave_gateway.cli._main",side_effect=error), patch("sys.stderr",new_callable=io.StringIO) as output:
            self.assertEqual(main([]),1)
        data=json.loads(output.getvalue())["error"]
        self.assertEqual(data["tx_id"],"cli_tx")
        self.assertTrue(data["indeterminate"])

    def test_expired_unknown_execution_is_never_replayed(self):
        with TemporaryDirectory() as root:
            journal=TransactionJournal(Path(root)/"journal.sqlite3")
            journal.reserve("lost","local","exec","app01","hash",0.001)
            journal.update("lost","local","running")
            time.sleep(0.01)
            self.assertEqual(journal.reconcile_expired("other"),0)
            self.assertEqual(journal.reconcile_expired("local"),1)
            self.assertEqual(journal.reserve("lost","local","exec","app01","hash",10)["state"],"indeterminate")
            self.assertFalse(journal.request_cancel("lost","local"))

    def test_context_crosses_pool_without_resetting_deadline(self):
        context=OperationContext("root","app01","alice",time.monotonic()+0.3)
        with activate(context), ThreadPoolExecutor(max_workers=2) as pool:
            before=budget(20)
            time.sleep(0.03)
            after=pool.submit(bind_context(lambda: budget(20))).result()
            self.assertLess(after,before-0.01)
            context.cancel()
            with self.assertRaises(OperationError) as caught:
                pool.submit(bind_context(lambda: checkpoint("block"))).result()
            self.assertEqual((caught.exception.code,caught.exception.tx_id),("cancelled","root"))

    def test_owner_cancellation_and_protocol_notification(self):
        with TemporaryDirectory() as root:
            entered=threading.Event()
            control=Mock()
            def execute(*args,**kwargs):
                mark_dispatched(); entered.set()
                while True: checkpoint("remote.wait"); time.sleep(0.01)
            control.exec_powershell.side_effect=execute
            engine=engine_at(root,control)
            server=McpJsonRpcServer(engine)
            with ThreadPoolExecutor(max_workers=2) as pool:
                running=pool.submit(call,server,"node_exec",{"node":"@appliance","script":"echo fixture","tx_id":"cancel_me"},"alice",41)
                self.assertTrue(entered.wait(2))
                with identity("bob"):
                    with self.assertRaises(OperationError): engine.cancel_transaction("cancel_me")
                server.handle_message({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":41}},principal="bob")
                self.assertFalse(running.done())
                server.handle_message({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":41}},principal="alice")
                response=running.result(timeout=2)
            self.assertEqual(response["error"]["data"]["code"],"cancelled")
            self.assertTrue(response["error"]["data"]["indeterminate"])
            self.assertEqual(engine.journal.get("cancel_me","alice")["state"],"indeterminate")

    def test_stdio_reads_cancellation_while_request_is_queued(self):
        with TemporaryDirectory() as root:
            control=Mock()
            def execute(*args,**kwargs):
                mark_dispatched()
                for _ in range(200):
                    checkpoint("fixture.wait"); time.sleep(0.005)
                self.fail("Queued cancellation was lost")
            control.exec_powershell.side_effect=execute
            engine=engine_at(root,control); server=McpJsonRpcServer(engine)
            request={"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"node_exec","arguments":{"node":"@appliance","script":"echo fixture","tx_id":"stdio_cancel"}}}
            cancel={"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":91}}
            source=io.StringIO(json.dumps(request)+"\n"+json.dumps(cancel)+"\n"); output=io.StringIO()
            server.serve_stdio(source,output)
            result=json.loads(output.getvalue())
            self.assertEqual(result["error"]["data"]["code"],"cancelled")
            self.assertIn(engine.journal.get("stdio_cancel","local")["state"],("cancelled","indeterminate"))

    def test_notification_arriving_before_engine_registration(self):
        with TemporaryDirectory() as root:
            control=Mock()
            engine=engine_at(root,control)
            with identity("alice"):
                engine.request_cancel_pending("early")
                with self.assertRaises(OperationError):
                    engine.exec_node("@appliance","echo fixture",tx_id="early")
            control.exec_powershell.assert_not_called()
            self.assertEqual(engine.journal.get("early","alice")["state"],"cancelled")

    @unittest.skipIf(os.name=="nt","POSIX owned-process test; Windows needs its own stand")
    def test_deadline_stops_owned_local_process_group(self):
        with TemporaryDirectory() as root:
            engine=engine_at(root)
            started=time.monotonic()
            with self.assertRaises(OperationError) as caught:
                engine.exec_node("@appliance","sleep 20",timeout_sec=0.15,tx_id="deadline")
            self.assertEqual(caught.exception.code,"deadline_exceeded")
            self.assertTrue(caught.exception.indeterminate)
            self.assertLess(time.monotonic()-started,2)

    def test_journal_failure_never_turns_into_automatic_replay(self):
        with TemporaryDirectory() as root:
            control=Mock(); control.exec_powershell.return_value=ExecResult(0,"ok","",1)
            engine=engine_at(root,control)
            original=engine.journal.update
            def fail_completion(tx_id,owner,state,**kwargs):
                if state in ("completed","failed","indeterminate"): raise OSError("fixture persistence failure")
                return original(tx_id,owner,state,**kwargs)
            engine.journal.update=fail_completion
            with self.assertRaises(OSError): engine.exec_node("@appliance","echo fixture",tx_id="uncertain")
            with self.assertRaises(OperationError): engine.exec_node("@appliance","echo fixture",tx_id="uncertain")
            self.assertEqual(control.exec_powershell.call_count,1)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.config=EnclaveConfig.from_dict({"targets":{"app01":{"host":"10.0.20.11"}}})
        self.grant=Grant("alice",("node_read_file","node_patch_file","node_transfer","node_http_request","enclave_transaction","node_sync"),
                         nodes=("app01",),read_roots={"app01":["/srv/allowed"]},write_roots={"app01":["/srv/allowed"]},destinations=("10.0.20.0/24",),allow_cancel=True)
        self.policy=AccessPolicy({"alice":self.grant})

    def test_tools_nodes_paths_and_network_fail_closed(self):
        self.policy.authorize("alice","node_read_file",{"node":"app01","remote_path":"/srv/allowed/file"},self.config)
        for tool,args in [("node_exec",{"node":"app01","script":"id"}),
                          ("node_read_file",{"node":"@appliance","remote_path":"/srv/allowed/file"}),
                          ("node_read_file",{"node":"app01","remote_path":"/srv/allowed/../secret"}),
                          ("node_http_request",{"node":"app01","url":"http://127.0.0.1/"}),
                          ("node_http_request",{"node":"app01","url":"http://app01.enclave.internal/"}),
                          ("node_sync",{"node":"app01","remote_dir":"/srv/other"})]:
            with self.subTest(tool=tool,args=args), self.assertRaises(OperationError):
                self.policy.authorize("alice",tool,args,self.config)
        self.policy.authorize("alice","node_http_request",{"node":"app01","url":"http://10.0.20.11/"},self.config)

    def test_diagnostic_grant_does_not_allow_repair(self):
        grant=Grant('viewer',('enclave_doctor',),nodes=('@appliance','@bastion'))
        policy=AccessPolicy({'viewer':grant})
        policy.authorize('viewer','enclave_doctor',{'fix':False},self.config)
        with self.assertRaises(OperationError): policy.authorize('viewer','enclave_doctor',{'fix':True},self.config)

    def test_per_tool_nodes_do_not_grant_controller_shell_via_status(self):
        grant=Grant('fixture',('node_exec','enclave_status'),nodes=('@appliance','@bastion','app01'),tool_nodes={'node_exec':['app01']},allow_arbitrary_exec=True)
        policy=AccessPolicy({'fixture':grant})
        policy.authorize('fixture','enclave_status',{},self.config)
        policy.authorize('fixture','node_exec',{'node':'app01','script':'id'},self.config)
        with self.assertRaises(OperationError): policy.authorize('fixture','node_exec',{'node':'@bastion','script':'id'},self.config)

    def test_windows_paths_reject_ads_traversal_and_ambiguous_names(self):
        root=[r"C:\allowed"]
        self.assertTrue(below(r"c:\allowed\file.txt",root))
        for path in (r"C:\allowed-other\file",r"C:\allowed\..\secret",r"C:\allowed\file:stream",r"C:\allowed\name.\file",r"C:\allowed\%TEMP%\file",r"C:\allowed\CON.txt"):
            self.assertFalse(below(path,root),path)

    def test_local_symlink_and_remote_reparse_check_before_read(self):
        with TemporaryDirectory() as root:
            root=Path(root); (root/"allowed").mkdir(); (root/"outside").mkdir()
            try: (root/"allowed/link").symlink_to(root/"outside",target_is_directory=True)
            except OSError: self.skipTest("Symlink creation unavailable")
            self.assertFalse(below(str(root/"allowed/link/file"),[str(root/"allowed")],local=True))
            engine=engine_at(root)
            with grant_scope(self.grant), self.assertRaises(OperationError):
                engine._verify_scoped_path("@appliance","/allowed/link/file",1)

    def test_mux_destination_grant_survives_listener_thread(self):
        transport=Mock(); scoped=ScopedMuxTransport(transport,self.policy,self.grant)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaises(OperationError): pool.submit(scoped.mux_open,"127.0.0.1",80).result()
            pool.submit(scoped.mux_open,"10.0.20.11",80).result()
        transport.mux_open.assert_called_once_with("10.0.20.11",80)

    def test_identity_is_not_accepted_from_payload_and_result_is_owner_scoped(self):
        with TemporaryDirectory() as root:
            engine=engine_at(root,Mock())
            server=McpJsonRpcServer(engine,policy=self.policy,principal="alice")
            denied=call(server,"node_exec",{"node":"app01","script":"id","actor":"admin"},"alice")
            self.assertIn("error",denied)
            with identity("bob"):
                engine.journal.reserve("foreign","bob","exec","app01","hash",10)
            response=call(server,"enclave_transaction",{"tx_id":"foreign"},"alice")
            self.assertEqual(response["error"]["data"]["code"],"transaction_not_found")
            tools=server.handle_message({"jsonrpc":"2.0","id":2,"method":"tools/list"})["result"]["tools"]
            self.assertNotIn("node_exec",{tool["name"] for tool in tools})

    def test_cancel_checks_node_grant_before_side_effect(self):
        with TemporaryDirectory() as root:
            engine=engine_at(root,Mock()); engine.journal.reserve("hidden","alice","exec","@appliance","hash",10)
            engine.cancel_transaction=Mock()
            server=McpJsonRpcServer(engine,policy=self.policy,principal="alice")
            response=call(server,"enclave_transaction",{"action":"cancel","tx_id":"hidden"},"alice")
            self.assertEqual(response["error"]["data"]["code"],"access_denied")
            engine.cancel_transaction.assert_not_called()

    def test_http_token_binds_identity_and_filters_discovery(self):
        with TemporaryDirectory() as root:
            engine=engine_at(root,Mock())
            engine.journal.reserve("alice_private","alice","exec","@appliance","hash",10)
            policy=AccessPolicy({"alice":Grant("alice",("enclave_transaction","enclave_capabilities"),nodes=("@appliance",)),
                                 "bob":Grant("bob",("enclave_transaction",),nodes=("@appliance",))})
            rpc=McpJsonRpcServer(engine,policy=policy,principal="alice")
            http=McpHttpServer(rpc,bind_port=0,principal_tokens={"fixture-alice-token":"alice","fixture-bob-token":"bob"})
            thread=threading.Thread(target=http.serve_forever,daemon=True); thread.start()
            deadline=time.monotonic()+3
            while http._httpd is None:
                if time.monotonic()>deadline: self.fail("HTTP server did not start")
                time.sleep(0.005)
            try:
                def request(method,path,payload=None,credential="fixture-bob-token"):
                    connection=client_module.HTTPConnection("127.0.0.1",http.bind_port,timeout=3)
                    body=json.dumps(payload) if payload is not None else None
                    connection.request(method,path,body,headers={"Authorization":"Bearer "+credential,"Content-Type":"application/json","X-Principal":"alice"})
                    response=connection.getresponse(); data=json.loads(response.read()); status=response.status; connection.close()
                    return status,data
                import http.client as client_module
                status,discovery=request("GET","/v1/tools")
                self.assertEqual(status,200)
                self.assertNotIn("enclave_capabilities",json.dumps(discovery))
                status,denied=request("POST","/tools/enclave_transaction",{"tx_id":"alice_private"})
                self.assertEqual(status,422)
                self.assertEqual(denied["data"]["code"],"transaction_not_found")
                self.assertEqual(request("POST","/tools/enclave_capabilities",{})[0],403)
                self.assertEqual(request("POST","/tools/enclave_capabilities",{},"fixture-alice-token")[0],200)
            finally:
                http.stop(); thread.join(3)

    def test_policy_typo_and_missing_tools_are_rejected(self):
        with TemporaryDirectory() as root:
            file=Path(root)/"policy.json"
            for values in ({"nodes":["*"]},{"tools":["*"],"allow_root":"false"},{"tools":["*"],"allow_rooot":True}):
                file.write_text(json.dumps({"principals":{"alice":values}}))
                with self.assertRaises(ValueError): AccessPolicy.load(file)


if __name__=="__main__": unittest.main()
