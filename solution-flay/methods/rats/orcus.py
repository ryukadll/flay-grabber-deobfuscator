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

Because it is .NET (C#), string literals in the #Strings heap are stored as
UTF-16LE. All fingerprints below are encoded as UTF-16LE accordingly.

Fingerprint tiers:

  HIGH CONFIDENCE (score +3 each) — unique to Orcus, not seen in clean software:
    "Orcus.Service.exe.gz"     — embedded watchdog component name (always present)
    "Orcus.Watchdog.exe.gz"    — embedded service component name (always present)
    "SOFTWARE\\\\Orcus"           — registry hive the RAT creates on install
    ".orcusInstallation"       — file extension used by the installer logic
    "OrcusUtilities"           — named-pipe IPC endpoint suffix
    "Orcus System Lock"        — title of the system-lock screen form

  MEDIUM CONFIDENCE (score +2 each) — strongly associated, rarely elsewhere:
    "schedulerInfo.xml"        — task-scheduler persistence file written by Orcus
    "PotentialCommand"         — internal base class name for plugin commands
    "Orcus.Properties.Resources" — embedded resource namespace (C# metadata)
    "orcus.plugins"            — embedded DLL resource name
    "orcus.staticcommands"     — embedded DLL resource name

  LOW CONFIDENCE (score +1 each) — present in Orcus, not unique alone:
    "Orcus.exe"                — default dropped executable name
    "Orcus.CodeExecution"      — code-execution plugin namespace
    "/forceInstall"            — command-line flag used during self-install

Detection threshold: score >= 5
"""

# ---------------------------------------------------------------------------
# Fingerprints (UTF-16LE — .NET string heap stores literals this way)
# ---------------------------------------------------------------------------

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
    """
    Return True if the binary scores >= 5 across OrcusRAT fingerprint tiers.

    Requires BSJB (.NET) header as a fast pre-filter. High-confidence markers
    score 3; medium 2; low 1. Any single high hit (3) plus any medium hit (2)
    clears the bar. Two high hits (6) alone are also sufficient.
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