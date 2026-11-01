"""Tracking decorator shared by CLI and service entry points."""

from __future__ import annotations

import functools
import hashlib
import inspect
import json
import secrets
import time
from dataclasses import asdict, is_dataclass

from enclave_gateway.operations.context import OperationContext, OperationError, activate, current, principal
from enclave_gateway.operations.journal import TERMINAL


def _serializable(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _serializable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_serializable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def tracked(operation: str):
    def decorate(function):
        signature = inspect.signature(function)
        @functools.wraps(function)
        def wrapped(self, *args, **kwargs):
            requested = kwargs.pop("tx_id", None)
            bound = signature.bind(self, *args, **kwargs)
            bound.apply_defaults()
            context = current()
            if context:
                if requested and requested != context.tx_id:
                    raise OperationError("nested_transaction_id", "dispatch", tx_id=context.tx_id)
                context.check(operation)
                if "timeout_sec" in bound.arguments:
                    bound.arguments["timeout_sec"] = context.remaining(bound.arguments["timeout_sec"])
                return function(*bound.args, **bound.kwargs)
            timeout = float(bound.arguments.get("timeout_sec", 120))
            started = time.monotonic()
            from enclave_gateway.operations.context import budget
            budget(timeout)
            tx_id = requested or "tx_" + secrets.token_hex(16)
            node = str(bound.arguments.get("node", "@appliance"))
            if len(node)>128 or not __import__('re').fullmatch(r'@?[A-Za-z0-9_.-]+',node):
                raise OperationError('invalid_node','dispatch',tx_id=tx_id)
            identity = principal()
            arguments = {key: _serializable(value) for key, value in bound.arguments.items() if key not in ("self", "actor", "timeout_sec")}
            fingerprint = hashlib.sha256(json.dumps(arguments, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            try:
                previous = self.journal.reserve(tx_id, identity, operation, node, fingerprint, timeout)
            except OperationError:raise
            except Exception as exc:
                raise OperationError('journal_unavailable','journal',tx_id=tx_id,node=node,
                                     message='Transaction reservation failed before command dispatch') from exc
            if previous:
                if previous["state"] in TERMINAL:
                    if previous.get('payload_status') in ('expired','archive_unavailable'):
                        raise OperationError('result_expired' if previous['payload_status']=='expired' else 'archive_unavailable', 'journal',tx_id=tx_id,node=node,message='Original outcome identity retained; automatic replay is forbidden')
                    if previous["error"] and not previous["result"]:
                        data = previous["error"]
                        raise OperationError(data["code"], data["stage"], tx_id=tx_id, node=node,
                                             indeterminate=data.get("indeterminate", False), message=data.get("message", ""))
                    saved = previous["result"]
                    if saved and saved.get("kind") == "exec":
                        from enclave_gateway.control.qga_client import ExecResult
                        return ExecResult(**saved["value"])
                    return saved["value"] if saved else None
                raise OperationError("transaction_indeterminate" if previous["state"] == "indeterminate" else "transaction_in_progress",
                                     "journal", tx_id=tx_id, node=node, indeterminate=True)
            context = OperationContext(tx_id, node, identity, started + timeout)
            with self._operations_lock:
                self._operations[tx_id] = context
                if (identity, tx_id) in self._pending_cancels:
                    context.cancelled.set()
                    self._pending_cancels.discard((identity, tx_id))
            captured=None
            try:
                with activate(context):
                    self.journal.update(tx_id, identity, "running")
                    value = function(*bound.args, **bound.kwargs)
                    if hasattr(value, "exit_code"):
                        value.tx_id = tx_id
                        value.timings_ms = dict(context.timings_ms)
                        kind = "exec"
                        state = "failed" if value.exit_code else "completed"
                    else:
                        kind, state = "mapping", "completed"
                        if isinstance(value, dict):
                            value["tx_id"] = tx_id
                            value["timings_ms"] = dict(context.timings_ms)
                    serialized = _serializable(value)
                    # Dataclass field names are protocol keys, never credential data.
                    saved = ({key: self.vault.scrubber.scrub(item) for key, item in serialized.items()}
                             if kind == "exec" else self.vault.scrubber.scrub(serialized))
                    captured={"kind":kind,"value":saved}
                    if getattr(context,'worker_evidence',None): captured['worker_evidence']=context.worker_evidence
                    context.check("completed")
                    self.journal.update(tx_id, identity, state, result=captured, timings=context.timings_ms)
                    return value
            except BaseException as exc:
                error = exc if isinstance(exc, OperationError) else OperationError(
                    "deadline_exceeded" if isinstance(exc, TimeoutError) else "operation_failed", context.stage,
                    tx_id=tx_id, node=node, indeterminate=context.dispatched,
                    message=self.vault.scrubber.scrub(str(exc))[:8192])
                try:
                    exc.operation_error = error
                except (AttributeError, TypeError):
                    pass
                state = "indeterminate" if error.indeterminate else "cancelled" if error.code == "cancelled" else "failed"
                if captured and error.code in ('cancelled','deadline_exceeded'):
                    # A late delivery/cancellation does not erase an already
                    # obtained terminal result. Keep it available by operation id.
                    error.indeterminate=False
                    error.known_outcome=True
                    state='failed' if kind=='exec' and value.exit_code else 'completed'
                data=error.as_dict()
                if getattr(error,'known_outcome',False): data['known_outcome']=True
                try:
                    self.journal.update(tx_id, identity, state, result=captured, error=data, timings=context.timings_ms)
                except Exception:
                    # Storage can fail after an effect but before its result is
                    # durable. The reserved identity remains; never replay it.
                    persistence=OperationError('journal_persistence_failed','journal',tx_id=tx_id,node=node,
                                               indeterminate=context.dispatched,
                                               message='Restore journal storage and reconcile the retained transaction identity')
                    try:exc.operation_error=persistence
                    except (AttributeError,TypeError):pass
                # Preserve established exception types for local callers.
                raise
            finally:
                with self._operations_lock:
                    self._operations.pop(tx_id, None)
                    self._pending_cancels.discard((identity, tx_id))
        return wrapped
    return decorate
