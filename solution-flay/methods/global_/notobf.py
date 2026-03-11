import os
from utils.deobfuscation import MatchWebhook, MatchWebhookInConst
from utils.decompile import strings, decompilePyc, consts_from_pyc


SCAN_EXTENSIONS = {".pyc", ".py", ".txt", ".cfg", ".ini", ".json", ".pyd", ".so", ".dll", ""}


class NotObfuscated:
    """
    Fallback handler for grabbers that are either completely unobfuscated or
    use lightweight / unknown obfuscation.

    Strategy (in order):
      1. Load each .pyc and scan co_consts directly (cleanest - no byte bleed).
      2. Decompile each .pyc with pycdc and scan the source text.
      3. Raw printable-byte extraction across all scannable files.
      4. Full raw scan of entrypoint bytes.
    """

    def __init__(self, dir, entries):
        self.extractiondir = dir
        self.entries = entries
        self.tempdir = os.path.join(self.extractiondir, "..", "..", "temp")

    def _scan_string(self, text: str):
        if not text:
            return None
        return MatchWebhook(text)

    def Deobfuscate(self):
        # ── pass 1: co_consts extraction (exact strings, no bleed) ───────────
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                if not fname.endswith(".pyc"):
                    continue
                path = os.path.join(root, fname)
                try:
                    consts = consts_from_pyc(path)
                    for c in consts:
                        result = MatchWebhookInConst(c)
                        if result:
                            return result
                except Exception:
                    pass

        # ── pass 2: decompile .pyc and scan source ────────────────────────────
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                if not fname.endswith(".pyc"):
                    continue
                path = os.path.join(root, fname)
                try:
                    source = decompilePyc(path)
                    result = self._scan_string(source)
                    if result:
                        return result
                except Exception:
                    pass

        # ── pass 3: raw printable-byte scan across all scannable files ────────
        for root, _, files in os.walk(self.extractiondir):
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SCAN_EXTENSIONS:
                    continue
                path = os.path.join(root, fname)
                try:
                    with open(path, "rb") as f:
                        raw = f.read()
                    extracted = strings(raw)
                    result = self._scan_string(extracted)
                    if result:
                        return result
                except Exception:
                    pass

        # ── pass 4: full raw bytes of entrypoints ─────────────────────────────
        for entry in self.entries:
            if "pyi" in entry:
                continue
            fpath = entry if os.path.isabs(entry) else os.path.join(self.extractiondir, entry)
            if not os.path.exists(fpath):
                continue
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                result = self._scan_string(raw.decode(errors="ignore"))
                if result:
                    return result
            except Exception:
                pass

        return None
