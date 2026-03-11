"""
Umbral Stealer deobfuscator — https://github.com/Blank-c/Umbral-Stealer

Umbral is a C# .NET stealer (not Python/PyInstaller). The builder patches
the webhook URL into the compiled payload.exe before delivery using AES-GCM
encryption via Windows BCrypt API.

How the webhook is stored in a built binary:
  - The builder writes three consecutive base64-encoded UTF-16LE entries into
    the .NET #US (user strings) heap at a fixed index:
      [i]   AES-256 key  — 32 bytes (b64len 44)
      [i+1] AES-GCM nonce — 12 bytes (b64len 16)
      [i+2] ciphertext blob — plaintext + 16-byte GCM tag appended
  - AESGCM(key).decrypt(nonce, blob, None) recovers the plaintext webhook URL.

Detection fingerprints (present in ALL Umbral binaries):
    b'Umbral.payload'  — C# namespace in .NET #Strings metadata heap
    b'Umbral Stealer'  — assembly title string
    b'.ligma'          — unique temp archive extension used by the stealer
"""

import re
import os
import base64
import struct

# ── Umbral identity fingerprints ──────────────────────────────────────────────
_FINGERPRINTS = [
    b"Umbral.payload",
    b"Umbral Stealer",
    b".ligma",
]

# ── ASCII regex (plain webhook if stored unencrypted) ─────────────────────────
_WEBHOOK_ASCII = re.compile(
    rb"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,90}"
)
_BOT_TOKEN_ASCII = re.compile(
    rb"[MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,45}"
)


def _u(s: str) -> bytes:
    """Convert an ASCII string to a UTF-16LE byte-regex fragment."""
    return b"".join(re.escape(bytes([ord(c)])) + b"\x00" for c in s)


# ── UTF-16LE regex (webhook stored in .NET #US heap) ─────────────────────────
_WEBHOOK_UTF16 = re.compile(
    _u("https://discord") +
    b"(?:" + _u("app") + b")?" +
    _u(".com/api/webhooks/") +
    b"(?:[0-9]\x00){17,20}" +
    _u("/") +
    b"(?:[a-zA-Z0-9_\x2d]\x00){60,90}"
)

_BOT_TOKEN_UTF16 = re.compile(
    b"[MN]\x00(?:[A-Za-z0-9]\x00){23,26}"
    b"\x2e\x00"
    b"(?:[A-Za-z0-9_\x2d]\x00){6}"
    b"\x2e\x00"
    b"(?:[A-Za-z0-9_\x2d]\x00){27,45}"
)


def _decode_utf16_match(m: re.Match) -> str:
    """Strip interleaved null bytes from a UTF-16LE regex match."""
    raw = m.group(0)
    return bytes(raw[i] for i in range(0, len(raw), 2)).decode("ascii", errors="ignore")


def _parse_us_heap(data: bytes) -> list[str]:
    """
    Parse the .NET #US (user strings) heap and return all string entries.
    Returns empty list if the PE cannot be parsed.
    """
    try:
        bsjb = data.find(b"BSJB")
        if bsjb < 0:
            return []
        pos = bsjb + 4 + 2 + 2 + 4
        vlen = struct.unpack_from("<I", data, pos)[0]; pos += 4
        pos += vlen + 2 + 2
        streams = {}
        for _ in range(5):
            if pos + 8 > len(data):
                break
            offset = struct.unpack_from("<I", data, pos)[0]; pos += 4
            size   = struct.unpack_from("<I", data, pos)[0]; pos += 4
            name_start = pos
            while pos < len(data) and data[pos] != 0:
                pos += 1
            name = data[name_start:pos].decode(errors="ignore")
            pos += 1; pos = (pos + 3) & ~3
            streams[name] = (bsjb + offset, size)

        if "#US" not in streams:
            return []

        us_off, us_size = streams["#US"]
        us_data = data[us_off:us_off + us_size]

        entries = []
        i = 1
        while i < len(us_data):
            b0 = us_data[i]
            if b0 == 0:
                i += 1
                continue
            if (b0 & 0xE0) == 0xE0:
                if i + 4 > len(us_data): break
                length = ((b0 & 0x1F) << 24) | (us_data[i+1] << 16) | (us_data[i+2] << 8) | us_data[i+3]
                i += 4
            elif (b0 & 0xC0) == 0x80:
                if i + 2 > len(us_data): break
                length = ((b0 & 0x3F) << 8) | us_data[i+1]
                i += 2
            else:
                length = b0 & 0x7F
                i += 1
            if length == 0 or i + length > len(us_data):
                i += 1
                continue
            raw = us_data[i:i + length - 1]
            i += length
            try:
                s = raw.decode("utf-16-le", errors="replace")
                if len(s) > 1:
                    entries.append(s)
            except Exception:
                pass
        return entries
    except Exception:
        return []


def _try_decrypt_umbral_webhook(data: bytes) -> str | None:
    """
    Attempt to decrypt the AES-GCM encrypted webhook from a built Umbral binary.

    The builder stores three *consecutive* entries in the .NET #US heap:
      [i]   key   — 32 bytes (base64-encoded, b64len=44)
      [i+1] nonce — 12 bytes (base64-encoded, b64len=16)
      [i+2] blob  — ciphertext with GCM tag appended (last 16B = tag)

    AESGCM.decrypt(nonce, blob, None) verifies the tag and returns plaintext.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return None

    entries = _parse_us_heap(data)
    if not entries:
        return None

    B64 = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")

    def try_b64(s: str):
        if not B64.match(s):
            return None
        pad = (4 - len(s) % 4) % 4
        try:
            return base64.b64decode(s + "=" * pad)
        except Exception:
            return None

    from utils.deobfuscation import MatchWebhook

    for i in range(len(entries) - 2):
        key = try_b64(entries[i])
        if key is None or len(key) != 32:
            continue
        nonce = try_b64(entries[i + 1])
        if nonce is None or len(nonce) != 12:
            continue
        ct_full = try_b64(entries[i + 2])
        if ct_full is None or len(ct_full) <= 32:
            continue
        # blob = ciphertext || GCM tag (last 16 bytes); AESGCM handles split
        try:
            aead = AESGCM(key)
            plaintext = aead.decrypt(nonce, ct_full, None)
            text = plaintext.decode(errors="replace")
            result = MatchWebhook(text)
            if result:
                return result
            for word in text.split():
                result = MatchWebhook(word)
                if result:
                    return result
        except Exception:
            pass

    return None


def is_umbral(data: bytes) -> bool:
    """Return True if raw binary bytes look like an Umbral Stealer payload."""
    return any(fp in data for fp in _FINGERPRINTS)


def extract_webhook(data: bytes) -> str | None:
    """
    Scan raw .NET PE bytes for a Discord webhook URL or bot token.
    Tries: plain ASCII, AES-GCM decryption, then UTF-16LE regex fallback.

    AES-GCM is checked before the UTF-16LE regex because encrypted ciphertext
    stored in the #US heap can accidentally match the bot-token pattern.
    """
    # ASCII pass (some builds / no obfuscation)
    m = _WEBHOOK_ASCII.search(data)
    if m:
        return m.group(0).decode("ascii")

    m = _BOT_TOKEN_ASCII.search(data)
    if m:
        return m.group(0).decode("ascii")

    # AES-GCM decryption pass — must run before UTF-16LE regex to avoid
    # false positives from ciphertext bytes in the #US heap
    result = _try_decrypt_umbral_webhook(data)
    if result:
        return result

    # UTF-16LE pass (#US heap plain string — fallback for unencrypted builds)
    m = _WEBHOOK_UTF16.search(data)
    if m:
        return _decode_utf16_match(m)

    m = _BOT_TOKEN_UTF16.search(data)
    if m:
        return _decode_utf16_match(m)

    return None


class UmbralDeobf:
    """
    Handles Umbral Stealer — a standalone C# .NET binary.
    """

    def __init__(self, filepath: str, entries: list = None):
        self.filepath = filepath
        self.entries = entries or []
        self._candidates: list[str] = []

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

            if not is_umbral(data):
                continue

            result = extract_webhook(data)
            if result:
                return result

        return None

