"""
LimeRAT detector — https://github.com/NYAN-x-CAT/Lime-RAT

LimeRAT is an open-source VB.NET RAT with an unusually wide feature set:
remote shell, keylogger, ransomware, crypto miner (XMRig), DDoS, USB spreader,
reverse proxy, HVNC, and a plugin loader. It has been widely distributed on
crimeware forums since ~2019 and has many forks and rebuilds.

Because it is VB.NET, all string literals are stored as UTF-16LE in the
binary — there are no meaningful ASCII fingerprints. All fingerprints below
are UTF-16LE encoded.
"""

# ---------------------------------------------------------------------------
# Fingerprints (all UTF-16LE)
# ---------------------------------------------------------------------------

_HIGH = [s.encode("utf-16-le") for s in [
    "LimeRAT-Admin",
    "Minning...",
    "Rans-Status",
    "xcvxcmv,nbxcvkmnbm",
]]

_MEDIUM = [s.encode("utf-16-le") for s in [
    "!PSend",
    "!PStart",
    "_PIN Error!",
    "_USB Error!",
    "Plugin Error!",
    "--donate-level=",
]]

_LOW = [s.encode("utf-16-le") for s in [
    "Flood!",
    "ff.exe",
    "Not encrypted",
]]

_THRESHOLD = 5


def is_limerat(data: bytes) -> bool:
    """
    Return True if the binary scores >= 5 across LimeRAT fingerprint tiers.

    Requires BSJB (.NET) header as a fast pre-filter; LimeRAT is VB.NET and
    all builds will have this marker. High-confidence markers score 3; medium
    2; low 1. A single high hit (3) plus any medium hit (2) clears the bar.
    Two high hits (6) alone are also sufficient.
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
