"""
Discord RAT detector and config extractor.

Covers the "Discord-RAT-2.0" family by moom825 and its many forks/rebuilds.

Detection strategy:
  • Only analyze .NET binaries (CLR signature "BSJB")
  • Require multiple indicators to avoid false positives
  • Weight unique implementation artifacts higher

NOTE:
Webhook / token extraction logic is unchanged.
"""

import re
import struct

_STRONG_ASCII = [
    b"CreateHostingChannel",
    b"session_channel_holder",
]

_STRONG_UTF16 = [s.encode("utf-16-le") for s in [
    "wss://gateway.discord.gg/?v=9&encording=json",  # unique typo
    "@here :white_check_mark: New session opened",
]]

_FINGERPRINTS_ASCII = [
    b"Discord_rat.Program",
    b"Discord_rat.WsClient",
    b"CommandHandler",
    b"Responsehandler",
    b"WsClient",
]

_FINGERPRINTS_UTF16 = [s.encode("utf-16-le") for s in [
    "https://discord.com/api/v9/guilds/{0}/channels",
    "session-",
]]

_TOKEN_RE = re.compile(
    r'^[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}$'
)

_SNOWFLAKE_RE = re.compile(r'^\d{17,20}$')

def _get_streams(data: bytes) -> dict:
    bsjb = data.find(b"BSJB")
    if bsjb < 0:
        return {}
    pos = bsjb + 4 + 2 + 2 + 4
    vlen = struct.unpack_from("<I", data, pos)[0]
    pos += 4 + vlen + 2 + 2
    num_streams = struct.unpack_from("<H", data, pos - 2)[0]
    streams = {}
    for _ in range(num_streams + 2):
        if pos + 8 > len(data):
            break
        offset = struct.unpack_from("<I", data, pos)[0]; pos += 4
        size   = struct.unpack_from("<I", data, pos)[0]; pos += 4
        name_start = pos
        while pos < len(data) and data[pos] != 0:
            pos += 1
        name = data[name_start:pos].decode(errors="ignore")
        pos += 1
        pos = (pos + 3) & ~3
        streams[name] = (bsjb + offset, size)
    return streams


def _get_us_strings(data: bytes) -> list:
    streams = _get_streams(data)
    if "#US" not in streams:
        return []
    us_off, us_size = streams["#US"]
    us_data = data[us_off: us_off + us_size]
    entries = []
    i = 1
    while i < len(us_data):
        b0 = us_data[i]
        if b0 == 0:
            i += 1
            continue
        if (b0 & 0xE0) == 0xE0:
            if i + 4 > len(us_data):
                break
            length = ((b0 & 0x1F) << 24) | (us_data[i+1] << 16) | (us_data[i+2] << 8) | us_data[i+3]
            i += 4
        elif (b0 & 0xC0) == 0x80:
            if i + 2 > len(us_data):
                break
            length = ((b0 & 0x3F) << 8) | us_data[i+1]
            i += 2
        else:
            length = b0 & 0x7F
            i += 1
        if length == 0 or i + length > len(us_data):
            i += 1
            continue
        raw = us_data[i: i + length - 1]
        i += length
        try:
            s = raw.decode("utf-16-le", errors="replace")
            if len(s) >= 2 and '\ufffd' not in s:
                entries.append(s)
        except Exception:
            pass
    return entries

def is_discordrat(data: bytes) -> bool:
    if b"BSJB" not in data:
        return False

    score = 0

    for fp in _STRONG_ASCII:
        if fp in data:
            score += 3

    for fp in _STRONG_UTF16:
        if fp in data:
            score += 3

    for fp in _FINGERPRINTS_ASCII:
        if fp in data:
            score += 1

    for fp in _FINGERPRINTS_UTF16:
        if fp in data:
            score += 1

    return score >= 3


def extract_config(data: bytes) -> dict:
    config = {"bot_token": None, "guild_id": None}
    try:
        us_strings = _get_us_strings(data)
    except Exception:
        return config

    for s in us_strings:
        if config["bot_token"] is None and _TOKEN_RE.match(s):
            config["bot_token"] = s
        elif config["guild_id"] is None and _SNOWFLAKE_RE.match(s):
            config["guild_id"] = s
        if config["bot_token"] and config["guild_id"]:
            break


    return config
