"""
OrcusRAT detector — https://github.com/Orcus2021/OrcusRAT (original by Orcus2021)

OrcusRAT (also known as Orcus) is a commercial .NET C# RAT that was widely sold
on crimeware forums from around 2016. The developer was arrested in 2019 but the
client has continued to circulate. It supports a rich plugin system, keylogging,
remote desktop, webcam access, system lock, watchdog, and more.

It ships as a single PE that embeds compressed copies of its own service
(Orcus.Service.exe.gz) and watchdog (Orcus.Watchdog.exe.gz) alongside a full
plugin framework. The client registers itself under SOFTWARE\\Orcus and uses a
named pipe (net.pipe://localhost/…/OrcusUtilities) for IPC.
"""


_HIGH = [s.encode("utf-16-le") for s in [
    "Orcus.Service.exe.gz",
    "Orcus.Watchdog.exe.gz",
    "SOFTWARE\\\\Orcus",
    ".orcusInstallation",
    "OrcusUtilities",
    "Orcus System Lock",
]]

_MEDIUM = [s.encode("utf-16-le") for s in [
    "schedulerInfo.xml",
    "PotentialCommand",
    "Orcus.Properties.Resources",
    "orcus.plugins",
    "orcus.staticcommands",
]]

_LOW = [s.encode("utf-16-le") for s in [
    "Orcus.exe",
    "Orcus.CodeExecution",
    "/forceInstall",
]]

_THRESHOLD = 5


def is_orcus(data: bytes) -> bool:
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
