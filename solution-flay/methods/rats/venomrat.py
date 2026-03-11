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

All string literals are UTF-16LE (standard .NET C# string heap).

Fingerprint tiers:

  HIGH CONFIDENCE (score +3 each) — unique to VenomRAT source, not in AsyncRAT:
    "VenomRATByVenom"              — hardcoded author/build tag, every build
    "HVNC_REPLY_MESSAGE"           — HVNC module reply opcode constant
    "HVNC_REPLY_CMP"               — HVNC module compressed-reply opcode
    "DataLogs_keylog_offline.txt"  — offline keylogger log filename
    "OfflineKeylog sending...."    — offline keylogger status string

  MEDIUM CONFIDENCE (score +2 each) — strongly associated, not in AsyncRAT:
    "HVNCStop"                     — HVNC stop command opcode
    "DataLogs.conf"                — VenomRAT local config/log filename
    "OfflineKeylogger"             — offline keylogger class/module name
    "DataLogs_keylog_online.txt"   — online keylogger log filename
    "keylogsetting"                — keylogger settings command opcode

  LOW CONFIDENCE (score +1 each) — present in Venom, may appear in other forks:
    "plu_gin"                      — underscore-obfuscated plugin opcode
    "save_Plugin"                  — plugin persistence opcode
    "loadofflinelog"               — offline log upload command
    "filterinfo"                   — process filter info opcode
    "runningapp"                   — running applications opcode
    "Windowssec.exe"               — default dropped executable name

Detection threshold: score >= 5
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