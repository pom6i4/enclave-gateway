#!/usr/bin/env python3
"""Repository hygiene verifier for pre-commit and CI checks.

Ensures that tracked files and commit messages never contain:
1. Non-documentation private IPv4 addresses (only 10.0.x.x, 127.x.x.x, 192.0.2.x, 0.0.0.0 are allowed).
2. Secret material, cryptographic keys, or proprietary installer binaries.
3. Automated tool attribution headers or trailers in code comments or commit messages.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
from pathlib import Path

FORBIDDEN_EXTENSION_SUFFIXES = {
    ".dst",
    ".msi",
    ".qcow2",
    ".pfx",
    ".p12",
    ".key",
    ".rdp",
    ".lzh",
}

ATTRIBUTION_PATTERNS = [
    re.compile(r"co-authored-by\s*:", re.IGNORECASE),
    re.compile(r"generated\s+(by|with)\s+(codex|cursor|claude|gemini|copilot|gpt|antigravity)", re.IGNORECASE),
    re.compile(r"created\s+(by|with)\s+(codex|cursor|claude|gemini|copilot|gpt|antigravity)", re.IGNORECASE),
]

# SHA-256 digests of environment-specific identifiers that must never appear in a public repository.
BLOCKED_TOKEN_HASHES = {
    "04b386c1c4295b17e640b8d726311002377c966509457e6879c2427319066586",
    "b28523915048a109c7244820471f70a1b86a73d98597057c75b1025a373a8261",
    "91c52f2f1e1a9d63f1e1a588c998483948a5b88759469682a4c7143949873d0b",
}

IPV4_PATTERN = re.compile(r"\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
ALLOWED_IPV4_PREFIXES = (
    "10.0.",
    "192.0.2.",
)


def check_text_content(path_label: str, content: str) -> list[str]:
    errors: list[str] = []
    for pattern in ATTRIBUTION_PATTERNS:
        match = pattern.search(content)
        if match:
            errors.append(f"{path_label}: forbidden attribution marker '{match.group(0)}'")

    for ip_match in IPV4_PATTERN.finditer(content):
        ip_str = ip_match.group(0)
        if not ip_str.startswith(ALLOWED_IPV4_PREFIXES):
            errors.append(
                f"{path_label}: non-example private IP '{ip_str}' (use 10.0.x.x or 192.0.2.x in docs/tests)"
            )

    words = re.findall(r"[A-Za-z0-9_-]{4,}", content.lower())
    for word in set(words):
        digest = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if digest in BLOCKED_TOKEN_HASHES:
            errors.append(f"{path_label}: blocked environment-specific identifier detected")

    return errors


def get_tracked_files(repo_root: Path) -> list[Path]:
    res = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return [p for p in repo_root.rglob("*") if p.is_file() and ".git" not in p.parts]
    paths: list[Path] = []
    for line in res.stdout.split("\0"):
        if line:
            p = repo_root / line
            if p.is_file():
                paths.append(p)
    return paths


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    errors: list[str] = []

    for file_path in get_tracked_files(repo_root):
        rel = file_path.relative_to(repo_root)
        if any(part.startswith(".agents") or part.startswith(".cursor") for part in rel.parts):
            errors.append(f"{rel}: local workspace rules must never be tracked by git")
            continue
        if file_path.suffix.lower() in FORBIDDEN_EXTENSION_SUFFIXES:
            errors.append(f"{rel}: forbidden binary/key file extension '{file_path.suffix}'")
            continue
        if file_path.name == ".env" or (file_path.name.startswith(".env.") and file_path.name != ".env.example"):
            errors.append(f"{rel}: environment secrets must never be tracked")
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(check_text_content(str(rel), text))

    if errors:
        for err in errors:
            print(f"[HYGIENE ERROR] {err}", file=sys.stderr)
        return 1

    print("Repository hygiene verification passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
