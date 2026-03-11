"""
NjRAT / Bladabindi detector

NjRAT (also known as Bladabindi) is a VB.NET RAT originally created around
2012-2013. It remains one of the most widely distributed RATs globally due
to its simplicity and many publicly available builders.

Detection uses a scoring system (like XWorm) to avoid false positives,
since several individual fingerprints are too short or common on their own.

Fingerprint tiers:

  HIGH CONFIDENCE (score +3 each) — unique to NjRAT protocol:
    "|'|'|" UTF-16LE  — the NjRAT C2 packet field separator, appears in
                        every single build without exception
    "[endof]" UTF-16LE — NjRAT protocol end-of-message marker

  MEDIUM CONFIDENCE (score +2 each) — strongly associated, rarely elsewhere:
    "Fransesco" ASCII  — embedded author name in Fransesco variant (majority)
    "CsAntiProcess" ASCII — anti-analysis class, unique to NjRAT source
    "LORDDecrypt" ASCII   — decryption function name from NjRAT source
    "SoftwareMicrosoftWindowsCurrentVersionRun" UTF-16LE  — persistence key
                           stored as a single concatenated string, unique to NjRAT
    "SGFjS2Vk" UTF-16LE   — base64("HacKed"), hardcoded default mutex in NjRAT
    b"Microsoft.VisualBasic.MyServices" ASCII — VB.NET runtime namespace;
                           combined with other hits confirms VB.NET origin

  LOW CONFIDENCE (score +1 each) — present in NjRAT, also possible elsewhere:
    "fransesco" UTF-16LE  — lowercase variant author string
    "ctraik" UTF-16LE     — NjRAT internal command token
    "vn" UTF-16LE         — version/info opcode
    "rss" UTF-16LE        — remote shell opcode
    "kl" UTF-16LE         — keylogger opcode
    b"Stub.exe" ASCII     — default output filename in NjRAT builders
    b"LORDDecrypt" ASCII  — already counted above

Detection threshold: score >= 4
"""

import struct

# ---------------------------------------------------------------------------
# Fingerprints
# ---------------------------------------------------------------------------

# Score +3: unique NjRAT protocol markers
_HIGH = [
    "|'|'|".encode("utf-16-le"),   # field separator in ALL NjRAT builds
    "[endof]".encode("utf-16-le"), # end-of-message marker
]

# Score +2: strongly NjRAT-specific
_MEDIUM_ASCII = [
    b"Fransesco",            # author name, present in majority of builds
    b"CsAntiProcess",        # anti-analysis class unique to NjRAT source
    b"LORDDecrypt",          # decryption function in NjRAT source
]
_MEDIUM_UTF16 = [s.encode("utf-16-le") for s in [
    "SoftwareMicrosoftWindowsCurrentVersionRun",  # concatenated run key (NjRAT-specific)
    "SGFjS2Vk",              # base64("HacKed") — default mutex in all builders
    "EnviarPermisaoGerenciador",  # Portuguese method name unique to NjRAT source
]]

# Score +1: present in NjRAT, not unique enough alone
_LOW_ASCII = [
    b"Stub.exe",             # default output name in NjRAT builders
]
_LOW_UTF16 = [s.encode("utf-16-le") for s in [
    "fransesco",             # lowercase variant author string
    "ctraik",                # internal command token
    "rss",                   # remote shell opcode
    "kl",                    # keylogger opcode
    "vn",                    # version/info opcode
    "[k]",                   # keylog marker
    "[i]",                   # info marker
]]

_THRESHOLD = 4


def is_njrat(data: bytes) -> bool:
    """
    Return True if the binary scores >= 4 across NjRAT fingerprint tiers.

    Requires BSJB (.NET) header to be present as a fast pre-filter.
    High-confidence markers contribute 3 points each; medium 2; low 1.
    A single |'|'| separator (score 3) plus one medium hit (score 2)
    is sufficient. Two high hits alone (score 6) are also sufficient.
    """
    if b"BSJB" not in data:
        return False

    score = 0

    for fp in _HIGH:
        if fp in data:
            score += 3
            if score >= _THRESHOLD:
                return True

    for fp in _MEDIUM_ASCII:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return True

    for fp in _MEDIUM_UTF16:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return True

    for fp in _LOW_ASCII:
        if fp in data:
            score += 1

    for fp in _LOW_UTF16:
        if fp in data:
            score += 1

    return score >= _THRESHOLD