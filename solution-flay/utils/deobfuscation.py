import re, lzma, codecs, base64

WEBHOOK_REGEX = r"(https://((ptb\.|canary\.|development\.)?)discord(app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9\-_]{60,100})(?=[^a-zA-Z0-9\-_]|$)"
WEBHOOK_REGEX_BASE64 = r"(aHR0cHM6Ly9[\d\w+/]+=*)"
TELEGRAM_REGEX = r"(?<![./\w])([0-9]{8,12}:[a-zA-Z0-9_-]{35})(?![a-zA-Z0-9_-])"
TELEGRAM_REGEX_BASE64 = r"zT([a-zA-Z0-9]+==)z"
BOT_TOKEN_REGEX = r"([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,45})(?=[^A-Za-z0-9_-]|$)"

# Matches strings that look like raw base64 and are long enough to be a token/webhook
_B64_CANDIDATE = re.compile(r'^[A-Za-z0-9+/]{30,}={0,2}$')


def _try_b64_decode(s):
    """Attempt base64 decode with padding correction. Returns decoded string or None."""
    try:
        padded = s + "=" * (-len(s) % 4)
        decoded = base64.b64decode(padded).decode()
        if decoded.isprintable():
            return decoded
    except Exception:
        pass
    return None


def MatchWebhookInConst(value: str):
    """
    Check a single string constant (e.g. from co_consts) for a token or webhook.
    Also tries base64-decoding it in case the grabber stores the value encoded.
    """
    # direct match first
    result = MatchWebhook(value)
    if result:
        return result
    # try b64 decode if it looks like a base64 blob
    if _B64_CANDIDATE.match(value):
        decoded = _try_b64_decode(value)
        if decoded:
            result = MatchWebhook(decoded)
            if result:
                return result
    return None


def MatchWebhook(string):
    """
    Search a string for any of:
      - Discord webhooks (plain or base64-encoded)
      - Discord bot tokens
      - Telegram bot tokens (plain or wrapped base64)
    Returns the first match found, as a string (or list if multiple webhooks).
    Returns None if nothing is found.
    """
    # ── discord webhook (base64 prefix heuristic) ─────────────────────────────
    webhookb64_matches = re.findall(WEBHOOK_REGEX_BASE64, string)
    decoded_webhooks = []
    for candidate in webhookb64_matches:
        decoded = _try_b64_decode(candidate)
        if decoded and re.search(WEBHOOK_REGEX, decoded):
            hit = re.search(WEBHOOK_REGEX, decoded)
            url = hit.group(1)
            if url not in decoded_webhooks:
                decoded_webhooks.append(url)
    if decoded_webhooks:
        return decoded_webhooks if len(decoded_webhooks) > 1 else decoded_webhooks[0]

    # ── discord webhook (plain) ───────────────────────────────────────────────
    webhook_matches = re.findall(WEBHOOK_REGEX, string)
    if webhook_matches:
        webhooks = []
        for w in webhook_matches:
            url = w[0] if isinstance(w, tuple) else w
            if url not in webhooks:
                webhooks.append(url)
        return webhooks if len(webhooks) > 1 else webhooks[0]

    # ── discord bot token ─────────────────────────────────────────────────────
    bot_token_match = re.search(BOT_TOKEN_REGEX, string)
    if bot_token_match:
        return bot_token_match.group(1)

    # ── telegram token (wrapped base64) ──────────────────────────────────────
    telegramb64_match = re.search(TELEGRAM_REGEX_BASE64, string)
    if telegramb64_match:
        decoded = _try_b64_decode(telegramb64_match.group(1) + "=")
        if decoded:
            return decoded

    # ── telegram token (plain) ────────────────────────────────────────────────
    telegram_match = re.search(TELEGRAM_REGEX, string)
    if telegram_match:
        return telegram_match.group(1)

    return None


class BlankStage3Obj:
    def __init__(self, first, second, third, fourth):
        self.first = first
        self.second = second
        self.third = third
        self.fourth = fourth


def BlankStage3(assembly: bytes):
    bytestr = b"\xfd7zXZ\x00\x00" + assembly.split(b"\xfd7zXZ\x00\x00")[1]
    decompressed = lzma.decompress(bytestr)
    sanitized = decompressed.decode().replace(";", "\n")
    sanitized = re.sub(r"^__import__.*", "", sanitized, flags=re.M)
    return BlankStage3Obj(
        re.search(r'^____="(.*)"$', sanitized, re.MULTILINE).group(1),
        re.search(r'^_____="(.*)"$', sanitized, re.MULTILINE).group(1),
        re.search(r'^______="(.*)"$', sanitized, re.MULTILINE).group(1),
        re.search(r'^_______="(.*)"$', sanitized, re.MULTILINE).group(1)
    )

def BlankStage4(stage3Obj: BlankStage3Obj):
    pythonbytes = b""
    try:
        unrot = codecs.decode(stage3Obj.first, "rot13")
        pythonbytes = base64.b64decode(unrot + stage3Obj.second + stage3Obj.third[::-1] + stage3Obj.fourth)
        # this is just for testing, you can uncomment it if you want to see the deobfuscated binary object
        f = open("dump.bin", "wb")
        f.write(pythonbytes)
        f.close()
    except Exception as e:
        print(e)
        raise Exception(e)
    strings = codecs.decode(pythonbytes, 'ascii', errors='ignore')
    return MatchWebhook(strings)
