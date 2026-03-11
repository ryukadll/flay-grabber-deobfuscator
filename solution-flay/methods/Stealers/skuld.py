"""
Skuld Stealer deobfuscator — https://github.com/hackirby/skuld

Skuld is a Go-compiled Windows stealer. Go embeds all string literals
directly in the .rodata section of the binary as plain ASCII/UTF-8 text,
so no decryption is needed — the webhook URL is always recoverable via regex.
"""

import os
import re

# -- Go runtime markers (survive -ldflags="-s -w")
_GO_MARKERS = [
    b"runtime.goexit",
    b"goroutine ",
    b"runtime.throw",
    b"Go build ID",
]

# -- Skuld-specific markers 
_SKULD_FINGERPRINTS = [
    b"github.com/hackirby/skuld",
    b"deathined",
    b"SecurityHealthSystray",
    b"skuld",
]

# -- Regex 
_WEBHOOK_RE = re.compile(
    rb"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,100}"
)
_BOT_TOKEN_RE = re.compile(
    rb"[MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,45}"
)


def is_go_binary(data: bytes) -> bool:
    return any(m in data for m in _GO_MARKERS)


def has_skuld_marker(data: bytes) -> bool:
    return any(fp in data for fp in _SKULD_FINGERPRINTS)


def is_skuld(data: bytes) -> bool:
    return is_go_binary(data) and has_skuld_marker(data)


def extract_webhook(data: bytes) -> str | None:
    m = _WEBHOOK_RE.search(data)
    if m:
        return m.group(0).decode("ascii", errors="ignore")

    m = _BOT_TOKEN_RE.search(data)
    if m:
        return m.group(0).decode("ascii", errors="ignore")

    return None


class SkuldDeobf:
    def __init__(self, filepath: str, entries: list = None):
        self.filepath = filepath
        self.entries = entries or []
        self._candidates = []

        if os.path.isfile(filepath):
            self._candidates = [filepath]
        elif os.path.isdir(filepath):
            for root, _, files in os.walk(filepath):
                for f in files:
                    if f.lower().endswith(".exe"):
                        self._candidates.append(os.path.join(root, f))

    def Deobfuscate(self) -> str | None:
        for path in self._candidates:
            try:
                with open(path, "rb") as fh:
                    data = fh.read()          
            except OSError:
                continue

            if not is_skuld(data):
                continue

            result = extract_webhook(data)
            if result:
                return result

        return None
