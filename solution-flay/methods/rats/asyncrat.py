"""
AsyncRAT detector — https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp

AsyncRAT is an open-source C# .NET RAT communicating over AES-encrypted TCP.
It has many forks: VenomRAT, SharpRAT, etc.

"""

_FINGERPRINTS_ASCII = [
    b"Client.Handle_Packet",
    b"Client.Algorithm",
    b"Client.Connection",
    b"Client.Install",
    b"Client.Helper",
    b"MutexControl",
    b"Serversignature",
    b"ValidateServerCertificate",
]


_STRONG_ASCII = [
    b"ReadServertData",  # typo preserved across AsyncRAT forks
]

_FINGERPRINTS_UTF16 = [s.encode("utf-16-le") for s in [
    "%Serversignature%",
    "%Certificate%",
    "Plugin.Plugin",
    "/// Client Buffersize ",
    "masterKey can not be null or empty.",
    "Invalid message authentication code (MAC).",
]]

_STRONG_UTF16 = [s.encode("utf-16-le") for s in [
    "ReadServertData",
]]


def is_asyncrat(data: bytes) -> bool:
    # Only check .NET assemblies
    if b"BSJB" not in data:
        return False

    score = 0

    # Strong ASCII indicators
    for fp in _STRONG_ASCII:
        if fp in data:
            score += 3

    # Strong UTF-16 indicators
    for fp in _STRONG_UTF16:
        if fp in data:
            score += 3

    # Normal ASCII indicators
    for fp in _FINGERPRINTS_ASCII:
        if fp in data:
            score += 1

    # Normal UTF-16 indicators
    for fp in _FINGERPRINTS_UTF16:
        if fp in data:
            score += 1

    return score >= 3