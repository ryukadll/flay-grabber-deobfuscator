"""
Doenerium deobfuscator — https://github.com/doener2323/doenerium

Doenerium is a JavaScript info-stealer built with Electron. The builder
packages the JS source into an app.asar archive which is either:
  - Embedded inside the output .exe (single-file Electron build)
  - Stored as resources/app.asar alongside the .exe

The webhook is set in config.js as the value of the 'webhook' key.
When built with 'dynamic encryption' (javascript-obfuscator), the strings
are hex-escaped (\\xNN) or unicode-escaped (\\uNNNN) but never truly
encrypted — they are still recoverable by decoding the escape sequences.

Detection fingerprints:
    b'doenerium'           — literal name embedded in package.json / JS
    b'electron'            — runtime identifier in the PE resources
    ASAR magic (\\x04\\x00\\x00\\x00) + JSON header containing {"files":

Extraction order:
    1. If input is a .exe  — scan binary for embedded ASAR magic
    2. If input is a dir   — look for resources/app.asar
    3. If input is a .asar — parse directly
    4. Walk all JS files in the ASAR; search for webhook via:
         a. Plain regex
         b. Hex-escape decode then regex
         c. Unicode-escape decode then regex
         d. Base64-candidate decode then regex
"""

import os
import re
import json
import struct
import base64

# -- Detection fingerprints ---------------------------------------------------
_FINGERPRINTS = [
    b"doenerium",
    b"Doenerium",
    b"REPLACE_ME",          # unbuilt placeholder in config.js
]

# ASAR header magic: first 4 bytes of every ASAR file
_ASAR_MAGIC = b"\x04\x00\x00\x00"

# -- Regex --------------------------------------------------------------------
_WEBHOOK_RE = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,100}"
)
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def _decode_hex_escapes(s: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _decode_unicode_escapes(s: str) -> str:
    return re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)


def _search_js(content: str) -> str | None:
    """Search JS source for a webhook URL across multiple decode passes."""
    for text in [
        content,
        _decode_hex_escapes(content),
        _decode_unicode_escapes(content),
        _decode_hex_escapes(_decode_unicode_escapes(content)),
    ]:
        m = _WEBHOOK_RE.search(text)
        if m:
            return m.group(0)

    # Base64 candidates inside the JS
    for candidate in _B64_CANDIDATE.findall(content):
        try:
            pad = (4 - len(candidate) % 4) % 4
            decoded = base64.b64decode(candidate + "=" * pad).decode("utf-8", errors="ignore")
            m = _WEBHOOK_RE.search(decoded)
            if m:
                return m.group(0)
        except Exception:
            pass

    return None


# -- ASAR parser --------------------------------------------------------------

def _parse_asar(data: bytes, base_offset: int = 0) -> dict:
    """
    Parse an ASAR archive (or ASAR embedded at base_offset inside a larger binary).
    Returns a dict mapping file paths to their raw byte content.

    ASAR header format (little-endian uint32s):
        [0]  4          -- size of the first header field (always 4)
        [4]  total_sz   -- total size of header pickle
        [8]  inner_sz   -- size of inner pickle payload
        [12] json_len   -- length of the JSON header string
        [16] <JSON>     -- file tree as JSON
        <aligned to 4 bytes>
        <file data>
    """
    pos = base_offset
    try:
        if data[pos:pos+4] != _ASAR_MAGIC:
            return {}
        json_len = struct.unpack_from("<I", data, pos + 12)[0]
        if json_len <= 0 or pos + 16 + json_len > len(data):
            return {}
        header_json = data[pos + 16: pos + 16 + json_len]
        header = json.loads(header_json)
    except Exception:
        return {}

    # File data starts after the header, aligned to 4 bytes
    file_data_start = pos + 16 + json_len
    file_data_start = (file_data_start + 3) & ~3

    files = {}

    def _walk(node, path):
        if "files" in node:
            for name, child in node["files"].items():
                _walk(child, (path + "/" + name) if path else name)
        elif "offset" in node and "size" in node:
            try:
                offset = int(node["offset"])
                size = int(node["size"])
                start = file_data_start + offset
                if start + size <= len(data):
                    files[path] = data[start: start + size]
            except Exception:
                pass

    _walk(header, "")
    return files


def _find_asar_offset(data: bytes) -> int | None:
    """
    Scan a binary for an embedded ASAR archive.
    Returns the byte offset of the ASAR header, or None if not found.
    """
    pos = 0
    while pos < len(data) - 16:
        idx = data.find(_ASAR_MAGIC, pos)
        if idx < 0:
            break
        try:
            json_len = struct.unpack_from("<I", data, idx + 12)[0]
            if 16 < json_len < 5_000_000 and idx + 16 + json_len <= len(data):
                candidate = data[idx + 16: idx + 16 + json_len]
                if candidate.startswith(b"{"):
                    obj = json.loads(candidate)
                    if "files" in obj:
                        return idx
        except Exception:
            pass
        pos = idx + 1
    return None


def _extract_webhook_from_asar(asar_data: bytes, asar_offset: int = 0) -> str | None:
    """Parse an ASAR and search all JS files for a webhook URL."""
    files = _parse_asar(asar_data, asar_offset)
    if not files:
        return None

    def priority(path):
        name = path.split("/")[-1].lower()
        if name == "config.js":
            return 0
        if name == "index.js":
            return 1
        if name.endswith(".js"):
            return 2
        return 3

    for path in sorted(files, key=priority):
        content_bytes = files[path]
        try:
            content = content_bytes.decode("utf-8", errors="replace")
        except Exception:
            continue
        result = _search_js(content)
        if result:
            return result

    return None


def is_doenerium(data: bytes) -> bool:
    """Return True if the binary looks like a Doenerium payload."""
    if any(fp in data for fp in _FINGERPRINTS):
        return True
    # Detect by ASAR presence + electron marker
    if b"electron" in data.lower() and _find_asar_offset(data) is not None:
        return True
    return False


def extract_webhook(data: bytes) -> str | None:
    """Extract a Discord webhook from a Doenerium binary or ASAR file."""
    # Raw ASAR file
    if data[:4] == _ASAR_MAGIC:
        return _extract_webhook_from_asar(data, 0)

    # Electron .exe with embedded ASAR
    offset = _find_asar_offset(data)
    if offset is not None:
        return _extract_webhook_from_asar(data, offset)

    # Raw JS content
    try:
        return _search_js(data.decode("utf-8", errors="replace"))
    except Exception:
        pass

    return None


class DoeneriumDeobf:
    """
    Handles Doenerium — an Electron-based JavaScript stealer.
    Accepts: built .exe, resources/app.asar file, or .asar file directly.
    """

    def __init__(self, filepath: str, entries: list = None):
        self.filepath = filepath
        self.entries = entries or []
        self._candidates = []

        if os.path.isfile(filepath):
            self._candidates = [filepath]
        elif os.path.isdir(filepath):
            for root, dirs, files in os.walk(filepath):
                dirs[:] = [d for d in dirs if d != "node_modules"]
                for f in files:
                    if f.endswith(".asar") or f.endswith(".exe") or f.endswith(".js"):
                        self._candidates.append(os.path.join(root, f))

    def Deobfuscate(self) -> str | None:
        for path in self._candidates:
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue

            if path.endswith(".asar"):
                if data[:4] != _ASAR_MAGIC:
                    continue
                result = _extract_webhook_from_asar(data, 0)
            elif path.endswith(".js"):
                if b"webhook" not in data and not any(fp in data for fp in _FINGERPRINTS):
                    continue
                try:
                    result = _search_js(data.decode("utf-8", errors="replace"))
                except Exception:
                    continue
            else:
                if not is_doenerium(data):
                    continue
                result = extract_webhook(data)

            if result:
                return result

        return None
