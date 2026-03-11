# Thank you to meisr cuz yes
import re, base64, marshal, zlib, dis, bz2, lzma, gzip, os
from os import path
from utils.decompile import disassemblePyc, decompilePyc, strings
from utils.deobfuscation import MatchWebhook
from cryptography.fernet import Fernet


class OtherDeobf:
    """
    Handles grabbers with random or uncommon obfuscation schemes:
      - marshal + base64 + compression layers (any order / depth)
      - Vare obfuscation
      - Fernet-encrypted payloads
      - Plain exec/eval wrappers
      - Multi-pass bytecode unwrapping (up to MAX_DEPTH layers)
    """

    MAX_DEPTH = 12

    def __init__(self, dir, entries):
        self.extractiondir = dir
        self.entries = entries
        self.tempdir = path.join(self.extractiondir, "..", "..", "temp")

    # ── compression helpers ────────────────────────────────────────────────────

    @staticmethod
    def DetectCompression(bytecode: str):
        for name, mod in [("lzma", lzma), ("gzip", gzip), ("bz2", bz2), ("zlib", zlib)]:
            if re.search(rf"\b{name}\b", bytecode):
                return mod
        return None

    def DecompressBytecodeX(self, bytecode: str) -> str:
        """Unwrap one marshal/compress layer and return disassembled bytecode."""

        # ── base64 (both a2b_base64 and b64decode) → optional decompress → marshal ──
        is_b64 = (
            re.search(r"LOAD_ATTR\s+[0-9]+ \(a2b_base64\)", bytecode) or
            re.search(r"LOAD_ATTR\s+[0-9]+ \(b64decode\)", bytecode)
        )
        if is_b64:
            # LOAD_CONST can be single or double quoted, may span multiple lines
            encoded_match = re.search(r"LOAD_CONST\s+[0-9]+[^(]*\(['\"]([A-Za-z0-9+/=\n]+)['\"]\)", bytecode)
            if not encoded_match:
                raise ValueError("No base64 payload found in LOAD_CONST")
            encoded = encoded_match.group(1).replace("\n", "").strip()
            raw = base64.b64decode(encoded)

            # try decompress layers before marshal
            for decomp in (zlib.decompress, lzma.decompress, bz2.decompress, gzip.decompress):
                try:
                    raw = decomp(raw)
                    break
                except Exception:
                    pass

            try:
                newserialized = marshal.loads(raw)
                return dis.Bytecode(newserialized).dis()
            except Exception:
                raise ValueError("marshal.loads failed after base64 decode")

        # ── named compression module → marshal ────────────────────────────────
        compression = self.DetectCompression(bytecode)
        if compression:
            compressed_match = re.search(r"LOAD_CONST\s+[0-9]+[^(]*\(b['\"](.+?)['\"]\)", bytecode, re.DOTALL)
            if not compressed_match:
                # fallback: old-style (b'...') in plain text
                compressed_match = re.search(r"\(b'(.*)'\)", bytecode)
            if not compressed_match:
                raise ValueError("No compressed payload found")
            raw = compressed_match.group(1).encode().decode("unicode_escape", "ignore").encode("iso-8859-1")
            decompressed = compression.decompress(raw)
            serialized = marshal.loads(decompressed)
            return dis.Bytecode(serialized).dis()

        raise ValueError("No known unwrap pattern found in bytecode")

    # ── vare obfuscation ───────────────────────────────────────────────────────

    @staticmethod
    def DeobfuscateVare(bytecode: str) -> str:
        pattern = r"""        [0-9]{1,4}    LOAD_CONST\s+[0-9]{1,4}: '(.*?)'\r\n\s+[0-9]{1,4}    STORE_NAME\s+[0-9]{1,4}: [\d\w]+\r\n\s+[0-9]{1,4}    BUILD_LIST\s+[0-9]{1,4}\r\n\s+[0-9]{1,4}    LOAD_CONST\s+[0-9]{1,4}: \('(.*?)', '(.*?)', '(.*?)'\)"""
        matches = re.search(pattern, bytecode, re.MULTILINE)
        if not matches:
            raise ValueError("Vare pattern not found")
        key    = matches.group(1)
        first  = matches.group(2)
        second = matches.group(3)
        third  = matches.group(4)

        def decodearr(arr):
            arr = arr[::-1]
            return ''.join(chr(int(i)) for i in arr.split("|"))

        f      = Fernet(key)
        first  = decodearr(first)
        second = decodearr(second)
        third  = decodearr(third)

        decrypted    = f.decrypt(bytes.fromhex(first + third + second))
        decoded      = base64.b64decode(decrypted)
        decompressed = zlib.decompress(decoded)
        return decompressed.decode(errors="ignore")

    # ── eval/exec string extraction ───────────────────────────────────────────

    @staticmethod
    def TryExtractEvalExec(source: str):
        """Pull the inner payload from common exec/eval wrapper patterns."""

        # exec(marshal.loads(zlib.decompress(base64.b64decode("..."))))
        m = re.search(
            r"exec\(marshal\.loads\(zlib\.decompress\(base64\.b64decode\(['\"]([A-Za-z0-9+/=\n]+)['\"]\)\)\)\)",
            source
        )
        if m:
            try:
                raw = base64.b64decode(m.group(1).replace("\n", ""))
                raw = zlib.decompress(raw)
                code = marshal.loads(raw)
                return dis.Bytecode(code).dis()
            except Exception:
                pass

        # exec(marshal.loads(base64.b64decode("...")))
        m = re.search(
            r"exec\(marshal\.loads\(base64\.b64decode\(['\"]([A-Za-z0-9+/=\n]+)['\"]\)\)\)",
            source
        )
        if m:
            try:
                raw = base64.b64decode(m.group(1).replace("\n", ""))
                code = marshal.loads(raw)
                return dis.Bytecode(code).dis()
            except Exception:
                pass

        # exec(base64.b64decode("..."))
        m = re.search(r"exec\(base64\.b64decode\(b?['\"]([A-Za-z0-9+/=\n]+)['\"]\)\)", source)
        if m:
            try:
                return base64.b64decode(m.group(1).replace("\n", "")).decode(errors="ignore")
            except Exception:
                pass

        # exec(marshal.loads(binascii.a2b_base64(b'...')))
        m = re.search(r"exec\(marshal\.loads\(binascii\.a2b_base64\(b'(.*)'\)\)\)", source)
        if m:
            try:
                b64 = m.group(1).encode().decode("unicode_escape", "ignore").encode("iso-8859-1")
                decoded = base64.b64decode(b64)
                serialized = marshal.loads(decoded)
                return dis.Bytecode(serialized).dis()
            except Exception:
                pass

        # eval/exec(compile(b'...'))
        m = re.search(r"(?:exec|eval)\(compile\(b?['\"]([A-Za-z0-9+/=\\n]+)['\"]", source)
        if m:
            try:
                return base64.b64decode(m.group(1)).decode(errors="ignore")
            except Exception:
                pass

        return None

    # ── generic multi-layer unwrap ────────────────────────────────────────────

    def MultiLayerUnwrap(self, bytecode: str):
        """Keep peeling obfuscation layers until a webhook/token is found."""
        for _ in range(self.MAX_DEPTH):
            result = MatchWebhook(bytecode)
            if result:
                return result
            try:
                bytecode = self.DecompressBytecodeX(bytecode)
            except Exception:
                break
        return MatchWebhook(bytecode)

    # ── main entry ─────────────────────────────────────────────────────────────

    def Deobfuscate(self):
        entrypoint = None
        for i in self.entries:
            if "pyi" not in i:
                entrypoint = i

        if not entrypoint:
            raise Exception("No valid entrypoint found")

        # resolve full path
        entry_path = os.path.join(self.extractiondir, entrypoint) \
            if not os.path.isabs(entrypoint) else entrypoint

        if not os.path.exists(entry_path):
            raise Exception(f"Entrypoint not found: {entry_path}")

        # 1. Try decompile first (pycdc gives real source when possible)
        source = decompilePyc(entry_path)
        result = MatchWebhook(source)
        if result:
            return result

        # 2. Check for eval/exec wrappers in decompiled source
        inner = self.TryExtractEvalExec(source)
        if inner:
            result = MatchWebhook(inner)
            if result:
                return result

        # 3. Try disassembly path
        bytecode = disassemblePyc(entry_path)

        # Vare obfuscation
        if entrypoint == "Obfuscated.pyc":
            try:
                content = self.DeobfuscateVare(bytecode)
                result = MatchWebhook(content)
                if result:
                    return result
            except Exception:
                pass

        # 4. Multi-layer marshal/compress unwrap
        result = self.MultiLayerUnwrap(bytecode)
        if result:
            return result

        # 5. co_consts + raw string scan of all extracted .pyc files as last resort
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                if not fname.endswith(".pyc"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    from utils.decompile import consts_from_pyc
                    from utils.deobfuscation import MatchWebhookInConst
                    for c in consts_from_pyc(fpath):
                        result = MatchWebhookInConst(c)
                        if result:
                            return result
                except Exception:
                    pass
                try:
                    with open(fpath, "rb") as f:
                        raw_strings = strings(f.read())
                    result = MatchWebhook(raw_strings)
                    if result:
                        return result
                except Exception:
                    pass

        return None
