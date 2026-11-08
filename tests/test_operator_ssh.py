"""Exercise the Linux wire peer and the opt-in host/worker contract."""
import base64
import hashlib
import itertools
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from enclave_gateway.agents import operator_target
from enclave_gateway.config import BastionSpec, EnclaveConfig
from enclave_gateway.operations.context import OperationError
from enclave_gateway.security.attestation import verify
from enclave_gateway.transports.structured import StructuredSshExecutor, StructuredTransport

OPERATOR_SID = "S-1-5-21-1000"
WORKER = Path(operator_target.__file__).with_name("bastion_structured.ps1")


def operator_configuration(worker_sha256, policy_sha256):
    return {
        "appliance": {"hypervisor": "direct"},
        "bastion": {"appliance_spool_dir": r"C:\spool", "execution_profile": "structured_only",
                    "spool_protocol": "stream", "structured_backend": "operator",
                    "worker_policy_path": r"C:\Users\operator\AppData\Local\EnclaveGateway\worker-policy.json",
                    "worker_policy_sha256": policy_sha256},
        "security": {"mode": "standard", "require_signed_agents": False, "enforce_worker_attestation": True,
                     "worker_sha256": worker_sha256, "worker_account": OPERATOR_SID},
        "targets": {"app01": {"host": "10.0.20.11", "port": 22, "user": "fixture"}},
    }


class OperatorOnboardingTests(unittest.TestCase):
    def test_stage_rejects_wrong_policy_before_appliance_write(self):
        from enclave_gateway.onboarding import stage_agents
        cfg = EnclaveConfig.from_dict(operator_configuration(hashlib.sha256(WORKER.read_bytes()).hexdigest(), "b" * 64))
        with tempfile.TemporaryDirectory() as folder:
            policy = Path(folder) / "worker-policy.json"
            policy.write_text("{}")
            control = Mock()
            with self.assertRaisesRegex(ValueError, "approved policy SHA-256"):
                stage_agents(control, cfg, policy_source=policy)
            self.assertEqual(control.mock_calls, [])

    def test_config_and_preflight_require_the_unsigned_operator_pins(self):
        from enclave_gateway.diagnostics import preflight
        raw = operator_configuration(hashlib.sha256(WORKER.read_bytes()).hexdigest(), "b" * 64)
        cfg = EnclaveConfig.from_dict(raw)
        report = preflight(cfg)
        self.assertTrue(next(row["ok"] for row in report["checks"] if row["check"] == "agent_package"))
        self.assertEqual(report["appliance_mtu"], 1200)
        self.assertEqual(cfg.security.trusted_signers, [])
        for section, key, value in (
            ("security", "worker_account", ""), ("security", "worker_sha256", ""),
            ("security", "enforce_worker_attestation", False), ("bastion", "worker_policy_sha256", ""),
            ("bastion", "lease_seconds", 59), ("bastion", "lease_seconds", 86401),
            ("security", "require_signed_agents", True),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                EnclaveConfig.from_dict({**raw, section: {**raw[section], key: value}})

    def test_operator_staging_delivers_peer_and_pins_adapter_in_local_commands(self):
        from enclave_gateway.control.qga_client import ExecResult
        from enclave_gateway.onboarding import agent_bundle, stage_agents
        digest = hashlib.sha256(WORKER.read_bytes()).hexdigest()
        raw = operator_configuration(digest, "b" * 64)
        raw["bastion"]["lease_seconds"] = 86400
        for signed in (False, True):
            with self.subTest(signed=signed):
                raw["security"].update(require_signed_agents=signed, trusted_signers=["A" * 40] if signed else [])
                cfg = EnclaveConfig.from_dict(raw)
                control = Mock()
                control.exec_powershell.return_value = ExecResult(0, "", "", 0)
                receipt = stage_agents(control, cfg, execution_policy="" if signed else "RemoteSigned")
                self.assertEqual(set(receipt["files"]), {"bastion_structured.ps1", "operator_target.py"})
                payloads = {call.args[1].rsplit("\\", 1)[-1]: call.args[0] for call in control.write_bytes.call_args_list}
                self.assertEqual(payloads["operator_target.py"], Path(operator_target.__file__).read_bytes())
                publish = control.exec_powershell.call_args_list[1].args[0]
                self.assertIn("Get-FileHash", publish)
                self.assertEqual("Get-AuthenticodeSignature" in publish, signed)
                self.assertIn("operator_state_dir", receipt["bastion_copy_command"])
                self.assertNotIn("\n", receipt["bastion_copy_command"])
                self.assertIn(digest, receipt["bastion_copy_command"])
                self.assertIn('command="/usr/bin/python3 ', receipt["target_authorized_keys_prefix"])
                start = receipt["start_command"]
                self.assertIn("-LeaseSeconds 86400", start)
                self.assertIn("-OperatorOpenSsh", start)
                self.assertLess(start.index(digest), start.index("& $egwScript"))
                self.assertEqual("-RequireSignedAgents:$false" in start, not signed)
                self.assertEqual("-TrustedSignerThumbprints" in start, signed)
                self.assertEqual("Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force" in start, not signed)
                if signed:
                    with self.assertRaises(ValueError):
                        agent_bundle(cfg, execution_policy="RemoteSigned")
        raw["security"]["worker_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "pinned worker SHA-256"):
            agent_bundle(EnclaveConfig.from_dict(raw))


@unittest.skipIf(os.name == "nt", "The operator SSH peer runs on Linux")
class OperatorPeerTests(unittest.TestCase):
    def setUp(self):
        self.process = subprocess.Popen(
            [sys.executable, str(Path(operator_target.__file__))],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": "egw-operator-v1"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop)
        self.assertEqual(self.process.stdout.read(8), operator_target.READY)

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate(timeout=3)

    def request(self, *, command, payload=b"", timeout=1500, limit=10000):
        header = json.dumps({
            "id": "fixture_id", "command": command, "input_bytes": len(payload),
            "output_limit": limit, "timeout_ms": timeout,
        }).encode()
        self.process.stdin.write(f"{len(header):08x}".encode() + header + payload)
        self.process.stdin.flush()
        size = int(self.process.stdout.read(8), 16)
        result = json.loads(self.process.stdout.read(size))
        self.assertEqual(result["id"], "fixture_id")
        return result, self.process.stdout.read(result["output_bytes"]), self.process.stdout.read(result["error_bytes"])

    def test_one_session_preserves_binary_output_and_exit_status(self):
        binary = bytes(range(256)) * 32
        reply, output, error = self.request(command="cat; printf failure >&2; exit 7", payload=binary)
        self.assertEqual((reply["exit_code"], reply["indeterminate"], output, error), (7, False, binary, b"failure"))
        reply, output, error = self.request(command="printf second")
        self.assertEqual((reply["exit_code"], output, error), (0, b"second", b""))

    def test_expiry_retires_peer_and_kills_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected"
            import shlex
            reply, _, _ = self.request(command=f"(sleep 0.4; touch {shlex.quote(str(marker))}) & wait", timeout=70)
            self.assertTrue(reply["indeterminate"])
            self.assertEqual(self.process.wait(timeout=3), 0)
            import time
            time.sleep(.45)
            self.assertFalse(marker.exists())

    def test_peer_rejects_excess_budget_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected"
            import shlex
            with self.assertRaises(ValueError):
                self.request(command=f"touch {shlex.quote(str(marker))}", timeout=15001)
            self.assertNotEqual(self.process.wait(timeout=3), 0)
            self.assertFalse(marker.exists())

    def test_extended_protocol_raises_only_the_exec_budget(self):
        from io import BytesIO

        for operation, maximum in (("ssh_exec", 300000), ("ssh_push", 15000),
                                   ("ssh_pull", 15000), ("ssh_copy", 15000)):
            with self.subTest(operation=operation):
                fields = {"id": "fixture_id", "op": operation, "command": "true",
                          "input_bytes": 0, "output_limit": 1, "timeout_ms": maximum}
                header = json.dumps(fields).encode()
                self.assertEqual(operator_target._request(BytesIO(header), f"{len(header):08x}".encode(),
                                                          extended=True), fields)
                fields["timeout_ms"] += 1
                header = json.dumps(fields).encode()
                with self.assertRaisesRegex(ValueError, "Invalid operator request"):
                    operator_target._request(BytesIO(header), f"{len(header):08x}".encode(), extended=True)


class OperatorTransportTests(unittest.TestCase):
    def test_status_uses_operator_snapshot_and_displays_starting(self):
        import time
        from enclave_gateway.control.qga_client import ExecResult
        from test_field_reliability import engine_at

        class Control:
            state = {"status": "starting", "spool_protocol": "stream",
                     "execution_profile": "structured_only", "structured_backend": "operator",
                     "instance_id": "d" * 32, "worker_sha256": "a" * 64}
            age = 0

            def exec_powershell(self, script, timeout_sec):
                return ExecResult(0, "{}", "", 0)

            def read_file_snapshot(self, path):
                return json.dumps(self.state).encode(), time.time() - self.age

        cfg = EnclaveConfig.from_dict(operator_configuration("a" * 64, "b" * 64))
        with tempfile.TemporaryDirectory() as folder:
            control = Control()
            engine = engine_at(Path(folder), control, cfg)
            engine.hypervisor = Mock()
            engine.hypervisor.is_running.return_value = (True, 123)
            engine._direct_posix = False
            self.assertEqual(engine.status()["bastion"]["worker_state"]["status"], "starting")
            self.assertFalse(engine.status()["bastion"]["worker_healthy"])
            control.state["status"] = "running"
            self.assertTrue(engine.status()["bastion"]["worker_healthy"])
            control.age = 60
            self.assertFalse(engine.status()["bastion"]["worker_healthy"])

    def test_unsigned_attestation_rejects_each_mismatched_identity_pin(self):
        nonce = "e" * 64
        pins = dict(expected_sha256="b" * 64, expected_policy_sha256="c" * 64,
                    expected_account=OPERATOR_SID, expected_execution_profile="structured_only",
                    expected_execution_model="operator-openssh", require_signed=False)
        evidence = dict(protocol_revision=1, version="0.3.0", nonce=nonce, instance_id="a" * 32,
                        loaded_sha256="b" * 64, current_sha256="b" * 64, policy_sha256="c" * 64,
                        sid=OPERATOR_SID, execution_profile="structured_only", execution_model="operator-openssh")
        self.assertTrue(verify(evidence, nonce, **pins)["verified"])
        for key in ("nonce", "loaded_sha256", "current_sha256", "policy_sha256", "sid", "execution_profile", "execution_model"):
            with self.subTest(key=key), self.assertRaises(OperationError):
                verify({**evidence, key: "wrong"}, nonce, **pins)
        with self.assertRaises(OperationError):
            verify(evidence, nonce, **{**pins, "expected_account": ""})

    def test_chunked_copy_requires_attested_capability(self):
        transport, control = Mock(), Mock()
        transport._verify_dispatch.return_value = {"verified": True, "stream_upload_v1": True}
        executor = StructuredSshExecutor(transport, control, Mock())
        node = Mock(os="linux")
        with self.assertRaises(OperationError) as error:
            executor.copy_chunked("push", node, Path("artifact"), "/tmp/artifact", timeout_sec=120, as_root=False)
        self.assertEqual(error.exception.code, "chunked_copy_unavailable")
        transport.request.assert_not_called()
        self.assertEqual(control.mock_calls, [])

    def test_operator_never_downgrades_to_legacy_or_files(self):
        for options in ({"spool_protocol": "stream"}, {"execution_profile": "structured_only"}):
            with self.assertRaises(ValueError):
                BastionSpec(structured_backend="operator", worker_policy_sha256="b" * 64, **options)
        spec = BastionSpec(execution_profile="structured_only", structured_backend="operator",
                           spool_protocol="stream", worker_policy_sha256="b" * 64)
        transport = StructuredTransport(Mock(), spec)
        transport._dispatch_envelope = Mock(side_effect=AssertionError("Forbidden dispatch"))
        with self.assertRaises(OperationError):
            transport.exec_bastion("whoami")
        with self.assertRaises(OperationError):
            transport.mux_open("10.0.0.10", 22)

    def test_fresh_attestation_rejects_a_different_backend(self):
        nonce = hashlib.sha256(b"fixture").hexdigest()
        evidence = {
            "protocol_revision": 1, "version": "0.3.0", "nonce": nonce,
            "instance_id": "a" * 32, "loaded_sha256": "b" * 64, "current_sha256": "b" * 64,
            "execution_model": "foreground-openssh",
        }
        with self.assertRaisesRegex(OperationError, "backend mismatch"):
            verify(evidence, nonce, expected_sha256="b" * 64, require_signed=False,
                   expected_execution_model="operator-openssh")

    def test_stop_during_reply_wait_never_republishes(self):
        spec = BastionSpec(execution_profile="structured_only", structured_backend="operator",
                           spool_protocol="stream", worker_policy_sha256="b" * 64)
        instance = {"instance": "a" * 32, "worker_sha256": "b" * 64}
        class SnapshotControl(Mock):
            def read_file_snapshot(self, path):
                return self.snapshot

        control = SnapshotControl()
        control.stream_append.return_value = 0
        control.stream_read.return_value = b""
        transport = StructuredTransport(control, spec)
        for op, status, stamp, error_code, unknown in (
                ("attest", "running", 946684800, "session_pending_worker", False),
                ("ssh_exec", "stopped", 1794050100, "remote_indeterminate", True)):
            with self.subTest(op=op, status=status):
                control.snapshot = json.dumps({
                    "status": status, "instance_id": instance["instance"],
                    "worker_sha256": instance["worker_sha256"],
                }).encode(), stamp
                control.reset_mock()
                with patch.object(transport, "_stream_descriptor", return_value=instance), patch(
                    "enclave_gateway.transports.rdp_vfs.time.monotonic", side_effect=itertools.count(0, 2)
                ), self.assertRaises(OperationError) as result:
                    transport._dispatch_stream({"op": op, "tx_id": "fixture_id"}, None, 10, 0)
                self.assertEqual(result.exception.code, error_code)
                self.assertEqual(result.exception.indeterminate, unknown)
                control.stream_append.assert_called_once()


@unittest.skipUnless(os.name == "nt", "Requires native Windows ACLs")
class WindowsOperatorPolicyTests(unittest.TestCase):
    def powershell(self, command):
        encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")
        # A PowerShell 7 parent can export incompatible module paths for Windows PowerShell.
        environment = {key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        return subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                              env=environment, capture_output=True, text=True, errors="replace", timeout=30)

    def test_operator_owned_policy_rejects_everyone_writer_on_ntfs(self):
        with tempfile.TemporaryDirectory(prefix="egw-acl-") as folder:
            source = str(WORKER).replace("'", "''")
            policy = str(Path(folder) / "worker-policy.json").replace("'", "''")
            command = rf"""
$ErrorActionPreference='Stop'
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('{source}',[ref]$tokens,[ref]$errors)
if($errors.Count){{throw 'Worker parse error'}}
$fn=$ast.Find({{param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PolicyAcl'}},$false)
. ([scriptblock]::Create($fn.Extent.Text))
$path='{policy}'
[IO.File]::WriteAllText($path,'{{}}')
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.FileSecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow'))
$everyone=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($everyone,'Read','Allow'))
Set-Acl -LiteralPath $path -AclObject $acl
$lease=[IO.File]::Open($path,'Open','Read','Read')
try {{ Assert-PolicyAcl $path $sid.Value $true }} finally {{ $lease.Dispose() }}
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($everyone,'WriteData','Allow'))
Set-Acl -LiteralPath $path -AclObject $acl
try {{ Assert-PolicyAcl $path $sid.Value $true }} catch {{
    if($_.Exception.Message -eq 'Policy must not be writable by an unapproved principal'){{exit 0}}
    throw
}}
throw 'Accepted an Everyone writer'
"""
            result = self.powershell(command)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_generated_copy_command_creates_state_and_replaces_only_verified_adapter(self):
        from enclave_gateway.onboarding import agent_bundle, stage_agents
        from enclave_gateway.control.qga_client import ExecResult
        with tempfile.TemporaryDirectory(prefix="egw-copy-") as folder:
            root = Path(folder)
            sid = self.powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
            self.assertEqual(sid.returncode, 0, sid.stderr)
            policy = root / "worker-policy.json"
            state = root / "state"
            policy.write_text(json.dumps({"revision": 1, "owner_sid": sid.stdout.strip(), "operator_state_dir": str(state)}))
            raw = operator_configuration(hashlib.sha256(WORKER.read_bytes()).hexdigest(),
                                         hashlib.sha256(policy.read_bytes()).hexdigest())
            raw["bastion"].update(worker_policy_path=str(policy), bastion_spool_dir=str(root / "spool"))
            cfg = EnclaveConfig.from_dict(raw)
            files, _, identity, _ = agent_bundle(cfg)
            source = root / "spool" / "agents" / identity / WORKER.name
            source.parent.mkdir(parents=True)
            source.write_bytes(files[WORKER.name])
            control = Mock()
            control.exec_powershell.return_value = ExecResult(0, "", "", 0)
            copy_command = stage_agents(control, cfg)["bastion_copy_command"]
            destination = root / WORKER.name
            destination.write_text("old adapter")
            result = self.powershell(copy_command)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(destination.read_bytes(), files[WORKER.name])
            self.assertTrue(state.is_dir())
            source.write_text("changed adapter")
            result = self.powershell(copy_command)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Staged adapter hash mismatch", result.stderr)
            self.assertEqual(destination.read_bytes(), files[WORKER.name])

    def test_generated_copy_command_installs_policy_once_with_private_acl(self):
        from enclave_gateway.control.qga_client import ExecResult
        from enclave_gateway.onboarding import stage_agents
        with tempfile.TemporaryDirectory(prefix="egw-policy-") as folder:
            root = Path(folder)
            sid = self.powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
            self.assertEqual(sid.returncode, 0, sid.stderr)
            source = root / "approved.json"
            source.write_text(json.dumps({"revision": 1, "owner_sid": sid.stdout.strip(),
                                          "operator_state_dir": str(root / "state")}))
            policy = root / "operator" / "worker-policy.json"
            raw = operator_configuration(hashlib.sha256(WORKER.read_bytes()).hexdigest(),
                                         hashlib.sha256(source.read_bytes()).hexdigest())
            raw["bastion"].update(worker_policy_path=str(policy), bastion_spool_dir=str(root / "spool"))
            cfg = EnclaveConfig.from_dict(raw)
            control = Mock()
            control.exec_powershell.return_value = ExecResult(0, "", "", 0)
            receipt = stage_agents(control, cfg, policy_source=source)
            staged = root / "spool" / "agents" / receipt["bundle_sha256"]
            staged.mkdir(parents=True)
            (staged / WORKER.name).write_bytes(WORKER.read_bytes())
            (staged / policy.name).write_bytes(source.read_bytes())
            command = receipt["bastion_copy_command"]
            result = self.powershell(command)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(policy.read_bytes(), source.read_bytes())
            self.assertEqual((policy.parent / WORKER.name).read_bytes(), WORKER.read_bytes())
            path = str(policy).replace("'", "''")
            checked = self.powershell(f"(Get-Acl -LiteralPath '{path}').AreAccessRulesProtected")
            self.assertEqual(checked.stdout.strip(), "True", checked.stderr)
            policy.write_text("local policy to preserve")
            result = self.powershell(command)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Approved worker policy hash mismatch", result.stderr)
            self.assertEqual(policy.read_text(), "local policy to preserve")


@unittest.skipUnless(os.name != "nt" and os.environ.get("EGW_TEST_POWERSHELL"),
                     "Portable PowerShell/.NET Unix pipe fixture")
class OperatorWorkerTests(unittest.TestCase):
    def test_actual_cli_routes_through_stream_and_persistent_peer(self):
        self._exercise_worker(disconnect=False)

    def test_idle_ssh_disconnect_retires_heartbeat_and_preserves_evidence(self):
        self._exercise_worker(disconnect=True)

    def test_corrupt_upload_attachment_retires_worker_without_writing_target(self):
        self._exercise_worker(disconnect=False, corrupt_upload=True)

    def test_chunked_cli_copy_exceeds_stream_capacity_and_checks_each_block(self):
        self._exercise_worker(disconnect=False, chunked=True)

    def test_unsigned_adapter_under_operator_sid(self):
        self._exercise_worker(disconnect=False, unsigned=True)

    def test_unsigned_adapter_rejects_foreign_policy_writer(self):
        self._exercise_worker(disconnect=False, unsigned=True, foreign_writer=True)

    def test_extended_exec_and_timeout_keep_the_same_worker(self):
        self._exercise_worker(disconnect=False, extended=True)

    def _exercise_worker(self, *, disconnect, corrupt_upload=False, chunked=False, unsigned=False, foreign_writer=False, extended=False):
        import socket
        import time
        from enclave_gateway import cli
        from enclave_gateway.control.qga_client import DirectHostControlChannel
        from enclave_gateway.engine import EnclaveEngine
        from unittest.mock import patch
        import contextlib
        import io

        with tempfile.TemporaryDirectory(prefix="egw-op-", dir="/tmp") as directory:
            root = Path(directory).resolve()
            for name in ("state", "spool", "host"):
                (root / name).mkdir()
            policy = root / "policy.json"
            policy.write_text(json.dumps({
                "revision": 1, "owner_sid": OPERATOR_SID,
                "operator_state_dir": str(root / "state"),
                "targets": {"app01": {"host": "127.0.0.1", "port": 22, "user": "fixture",
                                      "allow_exec": True, "allow_transfer": True, "allow_sudo": False}},
            }))
            worker = root / "bastion_structured.ps1"
            script = WORKER.read_text()
            script = script.replace("if($env:OS -ne 'Windows_NT')", "if($false)")
            script = script.replace("$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value", "$sid='S-1-5-21-1000'")
            start = script.index("function Assert-Signature")
            end = script.index("function Operator-Remaining", start)
            signature_fixture = (
                "function Assert-Signature([string]$Path,[bool]$Microsoft=$false){"
                + ("if(-not $Microsoft){throw 'Unsigned adapter signature was checked'};" if unsigned else "")
                + "if($Microsoft){[IO.File]::WriteAllText((Join-Path $SpoolDir 'microsoft-checked'),'yes')};"
                + "return @{Status='Valid';SignerCertificate=@{Thumbprint='" + "A"*40 + "'}}}\n"
            )
            writer = "S-1-1-0" if foreign_writer else OPERATOR_SID
            acl_fixture = r"""
function Get-Acl {
    $acl=[pscustomobject]@{}
    $acl|Add-Member ScriptMethod GetOwner { [pscustomobject]@{Value='OWNER'} }
    $acl|Add-Member ScriptMethod GetAccessRules {
        [pscustomobject]@{AccessControlType='Allow';FileSystemRights=2;IdentityReference=[pscustomobject]@{Value='WRITER'}}
    }
    return $acl
}
""".replace("OWNER", OPERATOR_SID).replace("WRITER", writer)
            script = script[:start] + signature_fixture + acl_fixture + script[end:]
            script = script.replace("Assert-PlainPath $ssh $true", "")
            start = script.index("function Open-OperatorPipes")
            end = script.index("function Open-OperatorSlot", start)
            script = script[:start] + r'''function Open-OperatorPipes{
                $flags=[IO.Pipes.PipeOptions]::Asynchronous
                $script:operatorInput=[IO.Pipes.NamedPipeServerStream]::new('fixtureIn','Out',1,'Byte',$flags)
                $script:operatorOutput=[IO.Pipes.NamedPipeServerStream]::new('fixtureOut','In',1,'Byte',$flags)
                $i=$operatorInput.WaitForConnectionAsync()
                $o=$operatorOutput.WaitForConnectionAsync()
                if(-not [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($i,$o),4000)){throw 'No pipe peer'}
                $requestTimer=[Diagnostics.Stopwatch]::StartNew()
                $protocol=if($extendedOperator){2}else{1}
                if([Text.Encoding]::ASCII.GetString((Operator-Read 8 4000)) -cne "EGWSSH$protocol`n"){throw 'Invalid peer'}
            }
''' + script[end:]
            # Preserve a causal failure message in the private fixture log.
            script = script.replace("            }catch{\n                $state=",
                                    "            }catch{\n                Write-Warning $_.Exception.ToString()\n                $state=")
            worker.write_text(script)
            policy_pin = hashlib.sha256(policy.read_bytes()).hexdigest()
            with (root / "worker.log").open("w+b") as log, contextlib.ExitStack() as stack:
                def stop_process(proc):
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                process = subprocess.Popen(
                    [os.environ["EGW_TEST_POWERSHELL"], "-NoProfile", "-File", str(worker),
                     "-SpoolDir", str(root/"spool"), "-PolicyPath", str(policy), "-PolicySha256", policy_pin,
                     *(["-RequireSignedAgents:$false"] if unsigned else ["-TrustedSignerThumbprints", "A"*40]),
                     "-OperatorOpenSsh", "-LeaseSeconds", "180",
                     *(["-OperatorExecMaxSec", "60"] if extended else [])],
                    env={**os.environ, "TMPDIR": directory}, stdout=log, stderr=log,
                )
                stack.callback(stop_process, process)
                if foreign_writer:
                    self.assertNotEqual(process.wait(timeout=10), 0)
                    self.assertIn("Policy must not be writable by an unapproved principal", (root/"worker.log").read_text())
                    self.assertFalse((root/"spool"/"worker_state.json").exists())
                    return
                peers=[]
                for name in ("fixtureIn", "fixtureOut"):
                    address=Path(directory)/("CoreFxPipe_"+name)
                    peer=stack.enter_context(socket.socket(socket.AF_UNIX))
                    for _ in range(300):
                        try:
                            peer.connect(str(address))
                            break
                        except (FileNotFoundError, ConnectionRefusedError):
                            self.assertIsNone(process.poll(), (root/"worker.log").read_text())
                            time.sleep(.01)
                    else:
                        self.fail((root/"worker.log").read_text())
                    peers.append(peer)
                server = subprocess.Popen(
                    [sys.executable, str(Path(operator_target.__file__))], stdin=peers[0], stdout=peers[1],
                    stderr=log, env={**os.environ, "SSH_ORIGINAL_COMMAND": "egw-operator-v2" if extended else "egw-operator-v1"},
                )
                stack.callback(stop_process, server)
                for peer in peers:
                    peer.close()
                for _ in range(300):
                    if (root/"spool"/"worker_state.json").is_file() and '"status":"running"' in (root/"spool"/"worker_state.json").read_text():
                        break
                    self.assertIsNone(process.poll(), (root/"worker.log").read_text())
                    time.sleep(.01)
                else:
                    self.fail((root/"worker.log").read_text())
                cfg = root/"config.json"
                raw = operator_configuration(hashlib.sha256(worker.read_bytes()).hexdigest(), policy_pin)
                if extended:
                    raw["bastion"]["operator_exec_max_sec"] = 60
                raw["security"].update(require_signed_agents=not unsigned, trusted_signers=[] if unsigned else ["A"*40])
                raw["security"]["agent_package_dir"] = str(root)
                raw["targets"]["app01"]["host"] = "127.0.0.1"
                cfg.write_text(json.dumps(raw))

                corrupt_part = False
                corrupt_download = False

                class StreamOnlyUploadControl(DirectHostControlChannel):
                    def write_file(self, *args, **kwargs):
                        raise AssertionError("The upload must use the attested Stream path")

                    def stream_fill_slot(self, path, data):
                        if corrupt_part and data == b"tail":
                            data = b"fail"
                        return super().stream_fill_slot(path, data)

                    def stream_read(self, path, offset, count=65536):
                        data = super().stream_read(path, offset, count)
                        if corrupt_download and count > 65536 and b"\n" in data and len(data) > 1024 * 1024:
                            return data[:-1] + bytes([data[-1] ^ 1])
                        return data

                    def stream_append(self, path, data, *, limit=None):
                        if corrupt_upload and len(data) > 1024 * 1024:
                            data = data[:-1] + bytes([data[-1] ^ 1])
                        return super().stream_append(path, data, limit=limit)

                def invoke(*args, expected=0):
                    out, err = io.StringIO(), io.StringIO()
                    with patch.object(cli, "EnclaveEngine", side_effect=lambda **kw: EnclaveEngine(
                        control_override=StreamOnlyUploadControl(root), **kw,
                    )), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        code = cli.main(["-c", str(cfg), "--state-dir", str(root/"host"), *args])
                    self.assertEqual(code, expected, out.getvalue()+err.getvalue()+(root/"worker.log").read_text()+(root/"spool"/"worker_state.json").read_text()+str((root/"spool"/"worker_state.json").stat().st_mtime-time.time()))
                    return out.getvalue(), err.getvalue()

                if unsigned:
                    self.assertEqual(json.loads(invoke("config", "check")[0])["execution_model"], "operator-openssh")
                    self.assertTrue(json.loads(invoke("doctor", "--preflight")[0])["healthy"])
                    command = invoke("agents", "command", "--execution-policy", "RemoteSigned")[0]
                    self.assertIn("-RequireSignedAgents:$false", command)
                    self.assertTrue((root/"spool"/"microsoft-checked").is_file())
                evidence=json.loads(invoke("agent-verify")[0])
                self.assertTrue(evidence["verified"])
                self.assertTrue(evidence["stream_upload_v1"])
                self.assertEqual(evidence["verified_checks"]["signer"], not unsigned)
                self.assertTrue(evidence["verified_checks"]["account"])
                self.assertTrue(evidence["verified_checks"]["policy"])
                self.assertTrue(evidence["stream_upload_deflate_v1"])
                self.assertTrue(evidence["chunked_copy_v1"])
                self.assertTrue(evidence["chunked_copy_slots_v1"])
                if extended:
                    self.assertEqual(evidence["operator_exec_max_sec"], 60)
                    self.assertIn("after-fifteen", invoke("exec", "app01", "sleep 16; printf after-fifteen", "--timeout", "25")[0])
                    _, err = invoke("exec", "app01", "sleep 5", "--timeout", "2", expected=1)
                    failure = json.loads(err)["error"]
                    self.assertTrue(failure["indeterminate"])
                    saved = json.loads(invoke("transactions", "get", failure["tx_id"])[0])
                    self.assertEqual(saved["state"], "indeterminate")
                    self.assertEqual(json.loads(invoke("agent-verify")[0])["instance_id"], evidence["instance_id"])
                command = "printf fixture-output\n#" + "x" * 8192
                self.assertIn("fixture-output", invoke("exec", "app01", command, "--timeout", "15")[0])
                upload, download, remote = root/"upload", root/"download", root/"remote"
                upload.write_bytes(random.Random(7).randbytes(1024 * 1024))
                remote_spec = "app01:"+str(remote)
                invoke("cp", str(upload), remote_spec, "--timeout", "15", expected=int(corrupt_upload))
                if corrupt_upload:
                    self.assertFalse(remote.exists())
                    process.wait(timeout=3)
                else:
                    invoke("cp", remote_spec, str(download), "--timeout", "15")
                    self.assertEqual(download.read_bytes(), upload.read_bytes())
                    upload.write_bytes(b"test" * (256 * 1024))
                    invoke("cp", str(upload), remote_spec, "--timeout", "15")
                    self.assertEqual(remote.read_bytes(), upload.read_bytes())
                if chunked:
                    payload = random.Random(23).randbytes(1024 * 1024)
                    with upload.open("wb") as stream:
                        for _ in range(65):
                            stream.write(payload)
                        stream.write(b"tail")
                    expected = hashlib.sha256(upload.read_bytes()).hexdigest()
                    remote = root / "target with 'quotes'"
                    remote_spec = "app01:" + str(remote)
                    remote.write_bytes(b"keep this until commit")
                    # Both directions cross the old 64 MiB request-stream limit.
                    for src, dst in ((str(upload), remote_spec), (remote_spec, str(download))):
                        result, _ = invoke("cp", src, dst, "--chunked", "--timeout", "120")
                        self.assertEqual(json.loads(result)["sha256"], expected)
                    self.assertEqual(hashlib.sha256(download.read_bytes()).hexdigest(), expected)
                    slot, = (root/"spool").glob("ipc_upload_*.bin")
                    self.assertEqual(slot.stat().st_size, 4096 + 1024 * 1024)
                    self.assertFalse(any(slot.read_bytes()))
                    req, = (root/"spool").glob("ipc_req_*.bin")
                    self.assertLess(req.stat().st_size, 4 * 1024 * 1024)
                    for data in (b"\x00", b""):
                        upload.write_bytes(data)
                        invoke("cp", str(upload), remote_spec, "--chunked")
                        invoke("cp", remote_spec, str(download), "--chunked")
                        self.assertEqual(download.read_bytes(), data)

                    upload.write_bytes(payload + b"tail")
                    invoke("cp", str(upload), remote_spec, "--chunked")
                    corrupt_download = True
                    download.write_bytes(b"keep local destination")
                    _, error = invoke("cp", remote_spec, str(download), "--chunked", expected=1)
                    self.assertIn("Download block checksum or length mismatch", error)
                    self.assertEqual(download.read_bytes(), b"keep local destination")
                    corrupt_download = False
                    corrupt_part = True
                    remote.write_bytes(b"keep remote destination")
                    invoke("cp", str(upload), remote_spec, "--chunked", "--timeout", "120", expected=1)
                    self.assertEqual(remote.read_bytes(), b"keep remote destination")
                    staged, = root.glob("target*.parts/payload")
                    self.assertEqual(staged.read_bytes(), payload)
                    self.assertEqual(slot.read_bytes()[0], 1)
                    process.wait(timeout=3)
                if corrupt_upload:
                    self.assertIn("Stream upload checksum mismatch", (root/"worker.log").read_text())
                elif chunked:
                    self.assertIn("Stream upload checksum mismatch", (root/"worker.log").read_text())
                elif disconnect:
                    stop_process(server)
                    self.assertNotEqual(process.wait(timeout=3), 0)
                    self.assertIn("OpenSSH disconnected", (root/"worker.log").read_text())
                    self.assertIn("session_pending_worker", invoke("agent-verify", expected=1)[1])
                else:
                    invoke("agents", "stop", "--timeout", "15")
                    self.assertEqual(process.wait(timeout=3), 0)

                from enclave_gateway.spool_cleanup import cleanup_script
                evidence = list((root/"spool").glob("ipc_*.bin"))
                self.assertTrue(evidence)
                cleaned = subprocess.run(
                    [os.environ["EGW_TEST_POWERSHELL"], "-NoProfile", "-Command",
                     cleanup_script(str(root/"spool"), execution_profile="structured_only",
                                    structured_backend="operator")],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(cleaned.returncode, 0, cleaned.stderr)
                details=json.loads(cleaned.stdout.split("APPLIANCE_CLEAN_OK:", 1)[1])
                self.assertTrue(details["stopped_worker_verified"])
                self.assertEqual(details["removed"], 0)
                self.assertTrue(all(path.exists() for path in evidence))
                self.assertTrue(list((root/"state"/".structured-transactions").glob("*.json")))
