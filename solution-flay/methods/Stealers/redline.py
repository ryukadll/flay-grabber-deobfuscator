"""
RedLine Stealer detector

RedLine is a C# .NET credential/data stealer sold as Malware-as-a-Service
since 2020. It communicates with its C2 over WCF (Windows Communication
Foundation) using net.tcp:// bindings, which is highly distinctive for a
stealer.
"""


_CLIENT_HIGH_ASCII = [
    b"FullInfoSender",
    b"PartsSender",
    b"Steanings",
]

_CLIENT_HIGH_UTF16 = [s.encode("utf-16-le") for s in [
    "SkyBox",
    "net.tcp://",
]]

_CLIENT_MEDIUM_ASCII = [
    b"System.ServiceModel",
    b"NetTcpBinding",
    b"ChannelFactory",
    b"ConfigReader",
    b"GameLauncher",
    b"FileSearcher",
    b"FileCopier",
    b"AllWallets",
    b"GetTokens",
    b"RosComNadzor",
]

_CLIENT_MEDIUM_UTF16 = [s.encode("utf-16-le") for s in [
    "ProjectManager",
    "SystemCache",
]]

_CLIENT_LOW_ASCII = [
    b"AesGcm256",
    b"XRails",
]

_CLIENT_LOW_UTF16 = [s.encode("utf-16-le") for s in [
    "PowerUp",
    "DisplayDown",
    "ProcessInfo",
    "*wallet*",
    "token_service",
]]



_PANEL_HIGH_UTF16 = [s.encode("utf-16-le") for s in [
    "RedLine.MainPanel.Properties.Resources",
    "RedLine.MainPanel.exe",
    "https://t.me/REDLINESUPPORT",
    "Libraries\\builder.exe",
]]

_PANEL_MEDIUM_UTF16 = [s.encode("utf-16-le") for s in [
    "GrabBrowsers",
    "GrabFiles",
    "GrabFTP",
    "BlacklistedCountry",
    "AntiDuplicate",
    "builderTab",
    "sorterTab",
]]

_PANEL_LOW_UTF16 = [s.encode("utf-16-le") for s in [
    "RedLinePanel",
    "buildIdTb",
    "serverIpTb",
]]

_THRESHOLD = 5


def _score(data: bytes, highs: list, mediums: list, lows: list) -> int:
    score = 0
    for fp in highs:
        if fp in data:
            score += 3
            if score >= _THRESHOLD:
                return score
    for fp in mediums:
        if fp in data:
            score += 2
            if score >= _THRESHOLD:
                return score
    for fp in lows:
        if fp in data:
            score += 1
    return score


def is_redline(data: bytes) -> bool:
    if b"BSJB" not in data:
        return False

    # Client path
    client_score = _score(
        data,
        _CLIENT_HIGH_ASCII + _CLIENT_HIGH_UTF16,
        _CLIENT_MEDIUM_ASCII + _CLIENT_MEDIUM_UTF16,
        _CLIENT_LOW_ASCII + _CLIENT_LOW_UTF16,
    )
    if client_score >= _THRESHOLD:
        return True

    # Panel path
    panel_score = _score(
        data,
        _PANEL_HIGH_UTF16,
        _PANEL_MEDIUM_UTF16,
        _PANEL_LOW_UTF16,
    )
    return panel_score >= _THRESHOLD

