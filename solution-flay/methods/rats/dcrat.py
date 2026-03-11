"""
DCRat (Dark Crystal RAT) detector

DCRat is a commercial C# .NET RAT sold on Russian cybercrime forums since 2019.
It uses TCP with AES-encrypted comms and a PHP-based C2 panel.
Original author pseudonyms: "boldenis44", "crystalcoder", "qwqdanchun".

NOTE: DCRat is very frequently distributed inside native C++ crypter stubs.
When crypted, the .NET payload is AES-encrypted inside the PE resource section
and none of the fingerprints below will be visible. Detection only works on
uncrypted or unpacked samples.
"""

_FINGERPRINTS_ASCII = [
    b"DCRat.Code",
    b"DCRat.Client",
    b"DCRat-Log#",
    b"ConfigPluginName",
    b"EncTable",
    b"ACTWindow",
    b"qwqdanchun",
    b"DCR_MUTEX-",
]

_FINGERPRINTS_UTF16 = [s.encode("utf-16-le") for s in [
    "DCRat-Log#",
    "DCRat.Code",
    "cao28Fn172GnuaZvuO_OnSystemInfoO29PluginI2bG7",
    "ConfigPluginName",
    "EncTable",
    "ACTWindow",
    "DCR_MUTEX-",
    "[Plugin] Invoke:",
    "[Clipboard] Saving information...",
    "Clipboard [Files].txt",
    "Clipboard [Text].txt",
    "uploadsafefile_name",
    "uploadfile_name",
    "@@EXTRACTLOCATION",
    "@@EXTRACT_EXISTING_FILE",
    "@@POST_UNPACK_CMD_LINE",
    "@@REMOVE_AFTER_EXECUTE",
]]


def is_dcrat(data: bytes) -> bool:
    if any(fp in data for fp in _FINGERPRINTS_ASCII):
        return True
    if any(fp in data for fp in _FINGERPRINTS_UTF16):
        return True

    return False
