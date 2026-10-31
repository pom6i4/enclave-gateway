"""Literal encoding for remote PowerShell and local OpenSSH configuration."""

from __future__ import annotations

import re


def ps_quote(value: str) -> str:
    if "\0" in value:
        raise ValueError("NUL is not permitted in command arguments")
    return "'" + value.replace("'", "''") + "'"


def validate_endpoint(host: str, port: int) -> None:
    if not host or not re.fullmatch(r"[A-Za-z0-9_.:%-]+", host) or host.startswith("-"):
        raise ValueError("Invalid endpoint host")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid endpoint port")


def ssh_config_quote(value: str) -> str:
    if any(ch in value for ch in "\r\n\0"):
        raise ValueError("Newlines are not permitted in SSH configuration values")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
