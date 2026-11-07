"""One monotonic time budget and verified identity across nested operations."""

from __future__ import annotations

import contextvars
import math
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterator


class OperationError(RuntimeError):
    def __init__(self, code: str, stage: str, *, tx_id: str = "", node: str = "", retryable: bool = False,
                 indeterminate: bool = False, message: str = "") -> None:
        self.code, self.stage = code, stage
        self.tx_id, self.node = tx_id, node
        self.retryable, self.indeterminate = retryable, indeterminate
        super().__init__(message or code.replace("_", " ").capitalize())

    def as_dict(self) -> dict:
        result={"code": self.code, "stage": self.stage, "tx_id": self.tx_id, "node": self.node,
                "retryable": self.retryable, "indeterminate": self.indeterminate, "message": str(self)}
        if getattr(self,'known_outcome',False): result['known_outcome']=True
        return result


@dataclass
class OperationContext:
    tx_id: str
    node: str
    principal: str
    deadline: float
    cancelled: threading.Event = field(default_factory=threading.Event)
    stage: str = "accepted"
    dispatched: bool = False
    timings_ms: dict[str, int] = field(default_factory=dict)
    _callbacks: dict[str, Callable[[], None]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def check(self, stage: str | None = None) -> None:
        if stage:
            self.stage = stage
        code = "cancelled" if self.cancelled.is_set() else "deadline_exceeded" if time.monotonic() >= min(self.deadline, _deadline_limit.get()) else ""
        if code:
            raise OperationError(code, self.stage, tx_id=self.tx_id, node=self.node, indeterminate=self.dispatched)

    def remaining(self, maximum: float | None = None) -> float:
        self.check()
        remaining = min(self.deadline, _deadline_limit.get()) - time.monotonic()
        return min(remaining, maximum) if maximum is not None else remaining

    def cancel(self) -> None:
        self.cancelled.set()
        with self._lock:
            callbacks = list(self._callbacks.values())
        for callback in callbacks:
            try:
                callback()
            except Exception:
                pass

    @contextmanager
    def cancellation_hook(self, key: str, callback: Callable[[], None]) -> Iterator[None]:
        with self._lock:
            self._callbacks[key] = callback
        try:
            self.check()
            yield
        finally:
            with self._lock:
                self._callbacks.pop(key, None)


_current: contextvars.ContextVar[OperationContext | None] = contextvars.ContextVar("egw_operation", default=None)
_principal: contextvars.ContextVar[str] = contextvars.ContextVar("egw_principal", default="local")
_track_dispatch: contextvars.ContextVar[bool] = contextvars.ContextVar("egw_track_dispatch", default=True)
_deadline_limit: contextvars.ContextVar[float] = contextvars.ContextVar("egw_deadline_limit", default=math.inf)


@contextmanager
def limit_deadline(seconds: float) -> Iterator[None]:
    """Cap nested IO while preserving the operation's cancellation and audit state."""
    token = _deadline_limit.set(min(_deadline_limit.get(), time.monotonic() + budget(seconds)))
    try:
        yield
    finally:
        _deadline_limit.reset(token)


def current() -> OperationContext | None:
    return _current.get()


def principal() -> str:
    return _principal.get()


@contextmanager
def identity(name: str) -> Iterator[None]:
    token = _principal.set(name)
    try:
        yield
    finally:
        _principal.reset(token)


@contextmanager
def activate(context: OperationContext) -> Iterator[None]:
    token = _current.set(context)
    try:
        context.check()
        yield
    finally:
        _current.reset(token)


def budget(maximum: float, stage: str = "") -> float:
    if not math.isfinite(maximum) or maximum <= 0:
        raise ValueError("Timeout must be a finite positive number")
    context = current()
    if context:
        context.check(stage or None)
        return context.remaining(maximum)
    deadline = _deadline_limit.get()
    if deadline == math.inf:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OperationError("deadline_exceeded", stage)
    return min(maximum, remaining)


def checkpoint(stage: str) -> None:
    context = current()
    if context:
        context.check(stage)
    elif _deadline_limit.get() != math.inf and time.monotonic() >= _deadline_limit.get():
        raise OperationError("deadline_exceeded", stage)


def mark_dispatched() -> None:
    context = current()
    if context:
        context.check()
        if _track_dispatch.get():
            context.dispatched = True


@contextmanager
def read_only_preflight() -> Iterator[None]:
    """Keep the caller's cancellation and deadline while reading readiness."""
    token = _track_dispatch.set(False)
    try:
        yield
    finally:
        _track_dispatch.reset(token)


@contextmanager
def timed(stage: str) -> Iterator[None]:
    checkpoint(stage)
    started = time.monotonic()
    try:
        yield
    finally:
        context = current()
        if context:
            with context._lock:
                context.timings_ms[stage] = context.timings_ms.get(stage, 0) + int((time.monotonic() - started) * 1000)


def bind_context(function):
    """Give each executor task its own Context copy, sharing only the operation."""
    parent = contextvars.copy_context()
    def bound(*args, **kwargs):
        return parent.copy().run(function, *args, **kwargs)
    return bound


@contextmanager
def owned_cleanup(seconds: float = 2.0):
    """Short independent budget only for cleanup of resources created by us."""
    parent = current()
    cleanup = OperationContext(parent.tx_id if parent else "cleanup", parent.node if parent else "", principal(), time.monotonic() + seconds)
    token = _deadline_limit.set(math.inf)
    try:
        with activate(cleanup):
            yield
    finally:
        _deadline_limit.reset(token)
