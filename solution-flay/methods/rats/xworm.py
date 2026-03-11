"""
XWorm RAT detector — https://github.com/moom825/xworm

XWorm is a C# .NET Remote Access Trojan (RAT) that communicates with a C2
server over TCP. Config values (Host, Port, KEY, SPL, Mutex, Group) are
AES-encrypted with Rijndael-256 and stored in the .NET #US heap — full
decryption requires the builder's hardcoded key which varies per build.
"""


_FINGERPRINTS_ASCII = [
    b"XClientKEY",
    b"XClientSPL",
    b"xworm-mutex",
    b"XClient.exe",
]

_FINGERPRINTS_UTF16 = [s.decode("ascii").encode("utf-16-le") for s in _FINGERPRINTS_ASCII]

_COMMAND_FINGERPRINTS_UTF16 = [
    "StartDDos".encode("utf-16-le"),
    "StopDDos".encode("utf-16-le"),
    "PCShutdown".encode("utf-16-le"),
    "OfflineKeylogger".encode("utf-16-le"),
    "RunRecovery".encode("utf-16-le"),
    "injRun".encode("utf-16-le"),
    "UACFunc".encode("utf-16-le"),
]


def is_xworm(data: bytes) -> bool:

    # Fast filter: ensure this is a .NET assembly
    if b"BSJB" not in data:
        return False

    score = 0

    # High-confidence command indicators
    for fp in _COMMAND_FINGERPRINTS_UTF16:
        if fp in data:
            score += 2

    # Config / builder indicators (ASCII)
    for fp in _FINGERPRINTS_ASCII:
        if fp in data:
            score += 1

    # Config / builder indicators (UTF-16)
    for fp in _FINGERPRINTS_UTF16:
        if fp in data:
            score += 1


    return score >= 3
