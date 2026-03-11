"""
VenomRAT detector — https://github.com/Anoncheg1/VenomRAT (public mirror)

VenomRAT is a C# .NET RAT that began as a direct fork of AsyncRAT but has
diverged significantly. Key additions over vanilla AsyncRAT include:

  - HVNC (Hidden Virtual Network Computing) module
  - Offline keylogger with local log files (DataLogs.conf)
  - Pastebin-based C2 fallback
  - Anti-analysis / anti-AV process kill list
  - Hardcoded author tag: "VenomRATByVenom"
  - Obfuscated opcode names using underscores (Po_ng, Pac_ket, plu_gin, etc.)

Because it inherits AsyncRAT's codebase it will score positively on the
AsyncRAT detector as well. VenomRAT MUST be checked first in the dispatcher
so it is not misclassified as AsyncRAT.
"""

# ---------------------------------------------------------------------------
# Fingerprints (all UTF-16LE)
# ---------------------------------------------------------------------------

_HIGH = [s.encode("utf-16-le") for s in [
    "VenomRATByVenom",
    "HVNC_REPLY_MESSAGE",
    "HVNC_REPLY_CMP",
    "DataLogs_keylog_offline.txt",
    "OfflineKeylog sending....",
]]

_MEDIUM = [s.encode("utf-16-le") for s in [
    "HVNCStop",
    "DataLogs.conf",
    "OfflineKeylogger",
    "DataLogs_keylog_online.txt",
    "keylogsetting",
]]

_LOW = [s.encode("utf-16-le") for s in [
    "plu_gin",
    "save_Plugin",
    "loadofflinelog",
    "filterinfo",
    "runningapp",
    "Windowssec.exe",
]]

_THRESHOLD = 5


def is_venomrat(data: bytes) -> bool:
    """
    Return True if the binary scores >= 5 across VenomRAT fingerprint tiers.

    Requires BSJB (.NET) header as a fast pre-filter. This detector MUST be
    called before is_asyncrat() in the dispatcher — VenomRAT inherits AsyncRAT
    strings and will otherwise be misclassified.

    High-confidence markers score 3; medium 2; low 1. A single high hit (3)
    plus any medium hit (2) clears the bar.
    """
    if b"BSJB" not in data:
        return False

    score = 0

    for fp in _HIGH:
        if fp in data:
            score += 3
            if score >= _THRESHOLD:
                return True

    for fp in _MEDIUM:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return True

    for fp in _LOW:
        if fp in data:
            score += 1


    return score >= _THRESHOLD
