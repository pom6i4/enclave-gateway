"""OS Keychain integration, .env loader, secret scrubber, and safety guardrails."""

from __future__ import annotations

import base64
import os
import platform
import re
import subprocess
import urllib.parse
from pathlib import Path

KEYCHAIN_SERVICE_PREFIX = "enclave-gateway"


class DestructiveOperationError(PermissionError):
    """Raised when a destructive command is attempted without explicit confirmation."""


DESTRUCTIVE_PATTERNS = [
    re.compile(r"\bdrop\s+(table|database|schema)\b", re.IGNORECASE),
    re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\s+\S+\s*(?:;|$)", re.IGNORECASE),
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$)", re.IGNORECASE),
    re.compile(r"\b(?:mkfs|fdisk|wipefs)\b", re.IGNORECASE),
    re.compile(r"\b(?:shutdown|reboot|poweroff|init\s+0)\b", re.IGNORECASE),
]


def verify_command_safety(command: str, confirm_destructive: bool = False) -> None:
    """Block destructive shell or SQL operations unless explicitly confirmed."""
    if confirm_destructive:
        return
    for pattern in DESTRUCTIVE_PATTERNS:
        match = pattern.search(command)
        if match:
            raise DestructiveOperationError(
                f"Destructive operation blocked ('{match.group(0)}'). "
                "Pass confirm_destructive=True to authorize execution."
            )


class SecretScrubber:
    """Redacts sensitive credentials from stdout, stderr, logs, and RPC responses."""

    def __init__(self, secrets: list[str] | None = None) -> None:
        self._tokens: set[str] = set()
        if secrets:
            for item in secrets:
                self.register(item)

    def register(self, secret: str | None) -> None:
        if not secret:
            return
        clean = secret.strip("\r\n")
        if len(clean) < 4:
            return
        self._tokens.add(clean)
        self._tokens.add(urllib.parse.quote(clean, safe=""))
        self._tokens.add(base64.b64encode(clean.encode("utf-8")).decode("ascii"))

    def scrub(self, text: str) -> str:
        if not text or not self._tokens:
            return text
        result = text
        for token in sorted(self._tokens, key=len, reverse=True):
            if token in result:
                result = result.replace(token, "[REDACTED]")
        return result


class SecretVault:
    """Retrieves and stores secrets across OS Keychain and local .env files."""

    def __init__(self, env_file: str | Path | None = None) -> None:
        self._env_cache: dict[str, str] = {}
        self.scrubber = SecretScrubber()
        self._load_env_file(env_file)

    def _load_env_file(self, env_file: str | Path | None) -> None:
        candidates = [Path(env_file)] if env_file else [Path(".env"), Path("config/.env")]
        for path in candidates:
            if path.is_file():
                for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = raw_line.strip().rstrip("\r")
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip().rstrip("\r")
                    if (val.startswith('"') and val.endswith('"')) or (
                        val.startswith("'") and val.endswith("'")
                    ):
                        val = val[1:-1]
                    self._env_cache[key] = val
                    if any(s in key.upper() for s in ("PASS", "SECRET", "TOKEN", "KEY")):
                        self.scrubber.register(val)
                break

    def get(self, key: str, default: str = "") -> str:
        """Resolve secret from environment, .env file, or OS Keychain (always stripping CR/LF)."""
        if not key:
            return default

        val = os.environ.get(key) or self._env_cache.get(key) or self._get_from_keychain(key)
        if val is None:
            return default
        clean = val.rstrip("\r\n")
        if any(s in key.upper() for s in ("PASS", "SECRET", "TOKEN", "KEY")):
            self.scrubber.register(clean)
        return clean

    def set_in_keychain(self, key: str, value: str) -> bool:
        """Store secret in the native OS credential vault."""
        clean = value.rstrip("\r\n")
        self.scrubber.register(clean)
        sys_name = platform.system()
        if sys_name == "Darwin":
            res = subprocess.run(
                [
                    "security",
                    "add-generic-password",
                    "-U",
                    "-a",
                    key,
                    "-s",
                    f"{KEYCHAIN_SERVICE_PREFIX}:{key}",
                    "-w",
                    clean,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode == 0
        if sys_name == "Linux":
            res = subprocess.run(
                [
                    "secret-tool",
                    "store",
                    "--label",
                    f"{KEYCHAIN_SERVICE_PREFIX}:{key}",
                    "service",
                    KEYCHAIN_SERVICE_PREFIX,
                    "account",
                    key,
                ],
                input=clean,
                capture_output=True,
                text=True,
                check=False,
            )
            return res.returncode == 0
        return False

    def _get_from_keychain(self, key: str) -> str | None:
        sys_name = platform.system()
        if sys_name == "Darwin":
            res = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-a",
                    key,
                    "-s",
                    f"{KEYCHAIN_SERVICE_PREFIX}:{key}",
                    "-w",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout.rstrip("\r\n")
        elif sys_name == "Linux":
            res = subprocess.run(
                ["secret-tool", "lookup", "service", KEYCHAIN_SERVICE_PREFIX, "account", key],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                return res.stdout.rstrip("\r\n")
        return None
