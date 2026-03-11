"""
Quasar RAT / Pulsar RAT detector

Quasar is an open-source C# .NET RAT (https://github.com/quasar/Quasar).
Pulsar is a widely-used feature-extended fork of Quasar.

Both share a common codebase and leave distinctive fingerprints in the .NET
binary — ASCII strings in the #Strings metadata heap and UTF-16LE strings in
the #US (user-string) heap.

"""


_STRONG_ASCII = [
    b"Client_ProcessedByFody",
    b"FodyVersion",
]

_STRONG_UTF16 = [s.encode("utf-16-le") for s in [
    "FrmRemoteChat",
]]


_FINGERPRINTS_ASCII = [
    # Quasar
    b"Quasar.Client",
    b"Quasar.Common",
    b"Quasar.Server",
    b"costura.quasar.common",
    b"costura.quasar.client",

    # Pulsar fork
    b"Pulsar.Client",
    b"Pulsar.Common",
    b"pulsar.common",
    b"costura.pulsar.common",
    b"costura.pulsar.client",
]


_FINGERPRINTS_UTF16 = [s.encode("utf-16-le") for s in [
    "Sendpacket",
    "Quasar Client",
    "Quasar.Client",
    "Quasar.Common",
    "Pulsar Client",
    "PulsarDesktop",
    "Pulsar.Client",
    "pulsar.common",
]]


def is_quasar(data: bytes) -> bool:
    """
    Return True if the binary is likely Quasar / Pulsar RAT.

    Scoring model:
        +2 strong indicators
        +1 normal indicators

    Detection threshold: score >= 3
    """

    # Only analyze .NET assemblies
    if b"BSJB" not in data:
        return False

    score = 0

    # Strong ASCII indicators
    for fp in _STRONG_ASCII:
        if fp in data:
            score += 2

    # Strong UTF-16 indicators
    for fp in _STRONG_UTF16:
        if fp in data:
            score += 2

    # Normal ASCII indicators
    for fp in _FINGERPRINTS_ASCII:
        if fp in data:
            score += 1

    # Normal UTF-16 indicators
    for fp in _FINGERPRINTS_UTF16:
        if fp in data:
            score += 1

    return score >= 3