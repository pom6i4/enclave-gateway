"""OS Keychain integration, .env loader, secret scrubber, and safety guardrails."""

from __future__ import annotations

import base64
import os
import platform
import re
import subprocess
import urllib.parse
import threading
import hashlib
from typing import Any
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
    """Detect common destructive operations; this is a guardrail, not a sandbox."""
    if confirm_destructive:
        return
    normalized = re.sub(r"/\*.*?\*/", " ", command, flags=re.DOTALL)
    normalized = normalized.replace("\\\n", "").replace("`\n", "")
    normalized = normalized.replace("'", "").replace('"', "")
    patterns = DESTRUCTIVE_PATTERNS + [
        re.compile(r"\brm\s+(?=[^;&|\n]*(?:--recursive|-[a-z]*r))(?=[^;&|\n]*(?:--force|-[a-z]*f))[^;&|\n]*\s/(?:\*|\s|$)", re.I),
        re.compile(r"\b(?:Clear-Disk|Format-Volume|Stop-Computer|Restart-Computer)\b", re.I),
    ]
    for pattern in patterns:
        match = pattern.search(normalized)
        if match:
            raise DestructiveOperationError(
                f"Destructive operation blocked ('{match.group(0)}'). "
                "Pass confirm_destructive=True to authorize execution."
            )


class SecretScrubber:
    """Redacts sensitive credentials from stdout, stderr, logs, and RPC responses."""

    _PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
    _PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
    _JWT_CANDIDATE = re.compile(r"[A-Za-z0-9_.-]+")
    _URI_PASSWORD = re.compile(r"(://[^:/@\s]+:)([^@\s]+)\Z")

    @classmethod
    def _mask_private_keys(cls, text):
        parts=[]
        cursor=0
        while begin:=cls._PEM_BEGIN.search(text,cursor):
            end=cls._PEM_END.search(text,begin.end())
            stop=end.end() if end else len(text)
            parts.extend((text[cursor:begin.start()],
                          '[REDACTED_PRIVATE_KEY]'+'\n'*text.count('\n',begin.start(),stop)))
            cursor=stop
            if not end:break
        parts.append(text[cursor:])
        return ''.join(parts)

    @staticmethod
    def _mask_jwt(match):
        candidate = match.group(0)
        parts = candidate.split('.')
        for header, payload, signature in zip(parts, parts[1:], parts[2:]):
            start = header.find('eyJ')
            if start >= 0 and len(header)-start >= 11 and payload.startswith('eyJ') and len(payload) >= 11 and len(signature) >= 8:
                return '[REDACTED_JWT]'
        return candidate

    def __init__(self, secrets: list[str] | None = None) -> None:
        self._tokens: set[str] = set()
        self._lock = threading.RLock()
        if secrets:
            for item in secrets:
                self.register(item)

    def register(self, secret: str | None) -> None:
        if not secret:
            return
        clean = secret.strip("\r\n")
        if not clean:
            return
        with self._lock:
            self._tokens.add(clean)
            self._tokens.add(urllib.parse.quote(clean, safe=""))
            self._tokens.add(base64.b64encode(clean.encode("utf-8")).decode("ascii"))

    def scrub(self, text: Any) -> Any:
        if isinstance(text, dict):
            return {self.scrub(k): self.scrub(v) for k, v in text.items()}
        if isinstance(text, (list, tuple)):
            return [self.scrub(item) for item in text]
        if not isinstance(text, str):
            return text
        if not text:
            return text
        result = text
        with self._lock:
            tokens = sorted(self._tokens, key=len, reverse=True)
        # Detect structured secrets before registered fragments can replace
        # their delimiters (for example a credential literally equal to PRIVATE).
        result = self._mask_private_keys(result)
        # Tokenize before matching credentials. Retrying an unbounded scheme or
        # JWT prefix at every character makes long scripts quadratic to scrub.
        if '.eyJ' in result:
            result = self._JWT_CANDIDATE.sub(self._mask_jwt, result)
        if '://' in result and '@' in result:
            pieces = result.split('@')
            for index in range(len(pieces)-1):
                piece=pieces[index]
                start=len(piece)
                while start and not piece[start-1].isspace():
                    start-=1
                pieces[index]=piece[:start]+self._URI_PASSWORD.sub(r"\1[REDACTED]",piece[start:])
            result = '@'.join(pieces)
        for token in tokens:
            if token in result:
                result = result.replace(token, "[REDACTED]" + "\n" * token.count("\n"))
        # Captured output can end midway through a registered credential. Redact
        # boundary fragments conservatively; never attempt to reconstruct secrets.
        for token in tokens:
            if len(token) >= 8:
                for length in range(min(len(token) - 1, len(result)), 3, -1):
                    if result.endswith(token[:length]):
                        result = result[:-length] + "[REDACTED]"
                        break
                for length in range(min(len(token) - 1, len(result)), 3, -1):
                    if result.startswith(token[-length:]):
                        result = "[REDACTED]" + result[length:]
                        break
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

        if key in os.environ:
            val = os.environ[key]
        elif key in self._env_cache:
            val = self._env_cache[key]
        else:
            try:
                val = self._get_from_keychain(key)
            except FileNotFoundError:
                val = None
        if val is None:
            return default
        clean = val.rstrip("\r\n")
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
        if sys_name == "Windows":
            dpapi_file = Path.home() / ".enclave_gateway" / f"{hashlib.sha256(key.encode()).hexdigest()}.dpapi"
            dpapi_file.parent.mkdir(parents=True, exist_ok=True)
            b64_val = base64.b64encode(clean.encode("utf-8")).decode("ascii")
            ps_cmd = (
                f"$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64_val}')); "
                f"$sec = ConvertTo-SecureString $s -AsPlainText -Force; "
                f"ConvertFrom-SecureString $sec | Set-Content -LiteralPath '{str(dpapi_file).replace(chr(39), chr(39)*2)}' -NoNewline"
            )
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
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
        elif sys_name == "Windows":
            dpapi_file = Path.home() / ".enclave_gateway" / f"{hashlib.sha256(key.encode()).hexdigest()}.dpapi"
            if dpapi_file.is_file():
                ps_cmd = (
                    f"$sec = Get-Content -LiteralPath '{str(dpapi_file).replace(chr(39), chr(39)*2)}' -Raw | ConvertTo-SecureString; "
                    f"[System.Net.NetworkCredential]::new('', $sec).Password"
                )
                res = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    return res.stdout.rstrip("\r\n")
        return None
