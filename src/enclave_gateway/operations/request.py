"""Separate interpreter source from request data carried on private IPC/stdin."""
from __future__ import annotations

import json


class PowerShellRequest(str):
    """String-compatible source with data that must never be interpolated into it.

    The data is sensitive, not encrypted. Control channels must preserve it and
    must not log it. A caller that converts this to an ordinary string loses the
    data and fails authentication rather than embedding a secret in source.
    """
    def __new__(cls, source, request_data=None):
        value = super().__new__(cls, source)
        value.request_data = dict(getattr(source, 'request_data', {}))
        for name, item in (request_data or {}).items():
            if name in value.request_data and value.request_data[name] != item:
                raise ValueError('Conflicting interpreter request data')
            value.request_data[name] = item
        if len(json.dumps(value.request_data).encode()) > 8 * 1024 * 1024:
            raise ValueError('Interpreter request data limit exceeded')
        return value
