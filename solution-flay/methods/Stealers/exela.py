import re
import os
import base64
import marshal

from utils.decompile import consts_from_pyc, strings
from utils.deobfuscation import MatchWebhook, MatchWebhookInConst

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

MAX_LAYERS = 15

# Also try to match params in decompiled/raw source as fallback
_KEY_RE   = re.compile(r"key\s*=\s*base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)")
_TAG_RE   = re.compile(r"tag\s*=\s*base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)")
_NONCE_RE = re.compile(r"nonce\s*=\s*base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)")
_DATA_RE  = re.compile(r"encrypted_data\s*=\s*base64\.b64decode\(['\"]([A-Za-z0-9+/=]+)['\"]\)")

_EXELA_SIGNATURES = [
    "DecryptString",
    "quicaxd",
    "Exela is a best stealer",
]


def _is_exela_code(code_obj) -> bool:
    """Check if a code object's co_names indicate Exela obfuscation."""
    names = getattr(code_obj, "co_names", ())
    # Classic nested variant: both names present
    if "DecryptString" in names and "encrypted_data" in names:
        return True
    if "DecryptString" in names and "exec" in names:
        return _extract_params_from_code(code_obj) is not None
    return False


def _extract_params_from_code(code_obj):
    consts = code_obj.co_consts
    if len(consts) < 4:
        return None

    def _is_b64(v):
        if not isinstance(v, str) or not v:
            return False
        try:
            base64.b64decode(v)
            return True
        except Exception:
            return False
    best = None
    run_start = None
    run_len = 0
    for i, c in enumerate(consts):
        if _is_b64(c):
            if run_start is None:
                run_start = i
            run_len += 1
            if run_len >= 4:
                best = (run_start, run_start + 1, run_start + 2, run_start + 3)
                best = (i - 3, i - 2, i - 1, i)
        else:
            run_start = None
            run_len = 0

    if best is None:
        # Fallback: classic layout at indices 0-3
        try:
            key   = base64.b64decode(consts[0])
            tag   = base64.b64decode(consts[1])
            nonce = base64.b64decode(consts[2])
            ct    = base64.b64decode(consts[3])
            return key, tag, nonce, ct
        except Exception:
            return None

    try:
        ki, ti, ni, ci = best
        key   = base64.b64decode(consts[ki])
        tag   = base64.b64decode(consts[ti])
        nonce = base64.b64decode(consts[ni])
        ct    = base64.b64decode(consts[ci])
        # Sanity check: key must be 16, 24, or 32 bytes (AES); tag 16; ct non-empty
        if len(key) not in (16, 24, 32) or len(tag) != 16 or len(ct) == 0:
            return None
        return key, tag, nonce, ct
    except Exception:
        return None


def _extract_params_from_source(text: str):
    km = _KEY_RE.search(text)
    tm = _TAG_RE.search(text)
    nm = _NONCE_RE.search(text)
    dm = _DATA_RE.search(text)
    if not all([km, tm, nm, dm]):
        return None
    try:
        return (
            base64.b64decode(km.group(1)),
            base64.b64decode(tm.group(1)),
            base64.b64decode(nm.group(1)),
            base64.b64decode(dm.group(1)),
        )
    except Exception:
        return None


def _decrypt_layer(key: bytes, nonce: bytes, tag: bytes, ct: bytes):
    """Decrypt one AES-GCM layer. Returns plaintext bytes or None."""
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        dec = cipher.decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None


def _find_exela_code_obj(root_code):
    import types as _types
    if _is_exela_code(root_code):
        return root_code
    for c in root_code.co_consts:
        if isinstance(c, _types.CodeType):
            result = _find_exela_code_obj(c)
            if result is not None:
                return result
    return None


def _peel_code_layers(code_obj):
    target = _find_exela_code_obj(code_obj)
    if target is None:
        return None
    code_obj = target

    params = _extract_params_from_code(code_obj)
    if params is None:
        return None

    key, tag, nonce, ct = params
    plaintext = _decrypt_layer(key, nonce, tag, ct)
    if plaintext is None:
        return None

    # Try to compile the decrypted layer and peel again
    for _ in range(MAX_LAYERS):
        try:
            next_code = compile(plaintext.decode(errors="ignore"), "<exela>", "exec")
            if _is_exela_code(next_code):
                params = _extract_params_from_code(next_code)
                if params is None:
                    break
                key, tag, nonce, ct = params
                plaintext = _decrypt_layer(key, nonce, tag, ct)
                if plaintext is None:
                    break
                continue
        except Exception:
            pass
        # no more layers - plaintext is the final payload
        break

    return plaintext.decode(errors="ignore") if plaintext else None


def _peel_source_layers(text: str):
    for _ in range(MAX_LAYERS):
        params = _extract_params_from_source(text)
        if params is None:
            return text  # no more layers
        key, tag, nonce, ct = params
        plaintext = _decrypt_layer(key, nonce, tag, ct)
        if plaintext is None:
            return None
        text = plaintext.decode(errors="ignore")
    return text


class ExelaDeobf:
    """Handles Exela v2 stealer (AES-GCM multi-layer obfuscation)."""

    def __init__(self, directory: str, entries: list):
        self.extractiondir = directory
        self.entries = entries
        self.tempdir = os.path.join(directory, "..", "..", "temp")

    def _load_and_peel(self, filepath: str):
        if not _CRYPTO_AVAILABLE:
            raise Exception("cryptography package not installed")

        # read raw bytes and try all pyc header offsets
        with open(filepath, "rb") as f:
            data = f.read()

        code_obj = None
        for offset in (16, 12, 8):
            try:
                code_obj = marshal.loads(data[offset:])
                break
            except Exception:
                continue

        if code_obj is None:
            return None

        if not _is_exela_code(code_obj):
            return None

        # peel layers starting from the code object
        final_text = _peel_code_layers(code_obj)
        if final_text:
            result = MatchWebhook(final_text)
            if result:
                return result
            # also scan each const individually (in case webhook is b64-encoded)
            for c in final_text.split():
                r = MatchWebhookInConst(c)
                if r:
                    return r

        return None

    def Deobfuscate(self):
        if not _CRYPTO_AVAILABLE:
            raise Exception("cryptography package not installed — cannot decrypt Exela payload")

        # ── pass 1: co_names detection + co_consts extraction per .pyc 
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                if not fname.endswith(".pyc"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    result = self._load_and_peel(fpath)
                    if result:
                        return result
                except Exception:
                    pass

        # ── pass 2: source-regex fallback (for decompiled .py files)
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        source = f.read()
                    if not any(sig in source for sig in _EXELA_SIGNATURES):
                        continue
                    final = _peel_source_layers(source)
                    if final:
                        result = MatchWebhook(final)
                        if result:
                            return result
                except Exception:
                    pass

        return None
