"""
StormKitty deobfuscator — https://github.com/LimerBoy/StormKitty

StormKitty is a C# .NET stealer that exfiltrates via Telegram.
The builder patches two config values into the compiled binary:
  - TelegramAPI  : Telegram bot token  e.g. "1234567890:ABCDEFGHIJKLMNOpqrstu_vwxyz1234567"
  - TelegramID   : Telegram chat ID    e.g. "-1001234567890"
"""

import os
import re
import base64
import struct

# -- Detection fingerprints 
_FINGERPRINTS = [
    b"StormKitty",
    b"LimerBoy",
    b"TelegramAPI",
    b"github.com/LimerBoy/StormKitty",
]

# -- Hardcoded AES key derivation parameters 
_PBKDF2_PASSWORD = b"https://github.com/LimerBoy/StormKitty"
_PBKDF2_SALT     = bytes([255, 64, 191, 111, 23, 3, 113, 119,
                          231, 121, 252, 112, 79, 32, 114, 156])
_PBKDF2_ITERS    = 1000
_PBKDF2_LEN      = 48    

# Lazy-derived — computed once on first use
_AES_KEY: bytes | None = None
_AES_IV:  bytes | None = None


def _get_aes_params() -> tuple[bytes, bytes]:
    global _AES_KEY, _AES_IV
    if _AES_KEY is None:
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=_PBKDF2_LEN,
                salt=_PBKDF2_SALT,
                iterations=_PBKDF2_ITERS,
            )
            key_iv = kdf.derive(_PBKDF2_PASSWORD)
            _AES_KEY = key_iv[:32]
            _AES_IV  = key_iv[32:48]
        except ImportError:
            return b"", b""
    return _AES_KEY, _AES_IV


def _decrypt_crypted(value: str) -> str | None:
    if value.startswith("ENCRYPTED:"):
        value = value[10:]
    elif value.startswith("CRYPTED"):
        value = value[7:]
    try:
        ct = base64.b64decode(value)
    except Exception:
        return None

    key, iv = _get_aes_params()
    if not key:
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()
        return pt.decode("utf-8", errors="replace")
    except Exception:
        return None


# -- Regex patterns

# Plain Telegram bot token in raw ASCII bytes
_TG_TOKEN_ASCII = re.compile(
    rb"[0-9]{8,12}:[A-Za-z0-9_\-]{35}"
)

# CRYPTED / ENCRYPTED: prefix followed by base64 in UTF-16LE
_CRYPTED_UTF16 = re.compile(
    b"(?:C\x00R\x00Y\x00P\x00T\x00E\x00D\x00|E\x00N\x00C\x00R\x00Y\x00P\x00T\x00E\x00D\x00:\x00)"
    b"(?:[A-Za-z0-9+/]\x00){20,}"
    b"(?:=\x00){0,2}"
)

# Plain Telegram bot token in UTF-16LE
_TG_TOKEN_UTF16 = re.compile(
    b"(?:[0-9]\x00){8,12}"
    b":\x00"
    b"(?:[A-Za-z0-9_\x2d]\x00){35}"
)


def _decode_utf16_str(raw: bytes) -> str:
    """Strip interleaved null bytes from a UTF-16LE match."""
    return bytes(raw[i] for i in range(0, len(raw), 2)).decode("ascii", errors="ignore")


def _parse_us_heap(data: bytes) -> list[str]:
    """Return all strings from the .NET #US heap."""
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
        us_data = data[us_off: us_off + us_size]
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
            raw = us_data[i: i + length - 1]
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


_TG_TOKEN_STR = re.compile(r"[0-9]{8,12}:[A-Za-z0-9_\-]{35}")

# Discord webhook — present in variant forks of StormKitty
_WEBHOOK_STR = re.compile(
    r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,100}"
)
_WEBHOOK_ASCII = re.compile(
    rb"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9_\-]{60,100}"
)
_WEBHOOK_UTF16 = re.compile(
    b"h\x00t\x00t\x00p\x00s\x00:\x00/\x00/\x00d\x00i\x00s\x00c\x00o\x00r\x00d\x00"
    b"(?:a\x00p\x00p\x00)?"
    b".\x00c\x00o\x00m\x00/\x00a\x00p\x00i\x00/\x00w\x00e\x00b\x00h\x00o\x00o\x00k\x00s\x00/\x00"
    b"(?:[0-9]\x00){17,20}"
    b"/\x00"
    b"(?:[a-zA-Z0-9_\x2d]\x00){60,100}"
)


def is_stormkitty(data: bytes) -> bool:
    """Return True if the binary looks like a StormKitty payload."""
    return any(fp in data for fp in _FINGERPRINTS)


def extract_token(data: bytes) -> str | None:
    token = None
    chat_id = None

    # -- Pass 1: plain ASCII 
    m = _WEBHOOK_ASCII.search(data)
    if m:
        return m.group(0).decode("ascii")

    m = _TG_TOKEN_ASCII.search(data)
    if m:
        token = m.group(0).decode("ascii")

    # -- Pass 2: #US heap — CRYPTED and plain strings 
    entries = _parse_us_heap(data)
    for entry in entries:
        if entry.startswith("CRYPTED") or entry.startswith("ENCRYPTED:"):
            pt = _decrypt_crypted(entry)
            if pt:
                mt = _TG_TOKEN_STR.search(pt)
                if mt and not token:
                    token = mt.group(0)
                # Chat IDs are plain integers, sometimes negative
                if pt.lstrip("-").isdigit() and not chat_id:
                    chat_id = pt.strip()
        else:
            # Plain string in heap — check Discord webhook first (variant forks)
            mw = _WEBHOOK_STR.search(entry)
            if mw:
                return mw.group(0)
            mt = _TG_TOKEN_STR.search(entry)
            if mt and not token:
                token = mt.group(0)
            if entry.lstrip("-").isdigit() and 6 <= len(entry.strip()) <= 14 and not chat_id:
                chat_id = entry.strip()

    # -- Pass 3: UTF-16LE regex on raw bytes 
    if not token:
        m = _WEBHOOK_UTF16.search(data)
        if m:
            return bytes(m.group(0)[i] for i in range(0, len(m.group(0)), 2)).decode("ascii", errors="ignore")

        m = _TG_TOKEN_UTF16.search(data)
        if m:
            token = _decode_utf16_str(m.group(0))

    # -- Pass 4: CRYPTED in raw UTF-16LE bytes 
    if not token:
        for m in _CRYPTED_UTF16.finditer(data):
            raw = m.group(0)
            crypted_str = bytes(raw[i] for i in range(0, len(raw), 2)).decode("ascii", errors="ignore")
            pt = _decrypt_crypted(crypted_str)
            if pt:
                mt = _TG_TOKEN_STR.search(pt)
                if mt:
                    token = mt.group(0)
                    break
                if pt.lstrip("-").isdigit() and not chat_id:
                    chat_id = pt.strip()

    if not token:
        return None

    # Return in flay's Telegram format: "TOKEN$CHATID" or "TOKEN$"
    return f"{token}${chat_id}" if chat_id else f"{token}$"


class StormKittyDeobf:

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

            if not is_stormkitty(data):
                continue

            result = extract_token(data)
            if result:
                return result

        return None
