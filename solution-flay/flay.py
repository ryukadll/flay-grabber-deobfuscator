import os
import re
import sys
import shutil
import time
from os.path import join, dirname, exists

from methods.Stealers.ben import BenDeobf
from methods.Stealers.blank import BlankDeobf, BlankVariantDetected
from methods.Stealers.empyrean import VespyDeobf
from methods.Stealers.exela import ExelaDeobf
from methods.Stealers.luna import LunaDeobf
from methods.global_.notobf import NotObfuscated
from methods.global_.other import OtherDeobf
from methods.Stealers.umbral import UmbralDeobf, is_umbral
from methods.Stealers.doenerium import DoeneriumDeobf, is_doenerium
from methods.Stealers.stormkitty import StormKittyDeobf, is_stormkitty
from methods.Stealers.skuld import SkuldDeobf, is_skuld, is_go_binary, extract_webhook as skuld_extract_webhook
from methods.rats.xworm import is_xworm
from methods.rats.quasar import is_quasar
from methods.rats.asyncrat import is_asyncrat
from methods.rats.venomrat import is_venomrat
from methods.rats.dcrat import is_dcrat
from methods.rats.discordrat import is_discordrat, extract_config as discordrat_extract_config
from methods.rats.njrat import is_njrat
from methods.Stealers.redline import is_redline
from methods.rats.limerat import is_limerat
from methods.rats.orcus import is_orcus
from utils.decompile import unzipJava, checkUPX
from utils.download import TryDownload
from utils.pyinstaller.pyinstaller import ExtractPYInstaller
from utils.pyinstaller.pyinstallerExceptions import ExtractionError
from utils.webhookspammer import Webhook
from utils.telegram import Telegram
from utils.bottoken import BotToken
from utils.config import Config
from utils.display import updateDisplayDiscord

# ── colours ────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── RAT family — used for display labelling ────────────────────────────────────
_RAT_TYPES = {
    "XWorm RAT", "Quasar/Pulsar RAT", "AsyncRAT", "VenomRAT", "DCRat",
    "Discord RAT", "NjRAT", "LimeRAT", "OrcusRAT",
}

# ── human-readable label map for result keys ───────────────────────────────────
_RESULT_LABELS = {
    "type":                "Grabber",
    "webhook":             "Webhook",
    "bot_token":           "Bot Token",
    "guild_id":            "Guild ID",
    "pyinstaller_version": "PyInstaller",
    "python_version":      "Python",
}

_ANSI_STRIP = re.compile(r"\033\[[0-9;]*m")

ASCII_ART = f"""{CYAN}
     ███████╗██╗      █████╗ ██╗   ██╗
     ██╔════╝██║     ██╔══██╗╚██╗ ██╔╝
     █████╗  ██║     ███████║ ╚████╔╝ 
     ██╔══╝  ██║     ██╔══██║  ╚██╔╝  
     ██║     ███████╗██║  ██║   ██║   
     ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝  
{DIM}{WHITE}            grabber deobfuscator
{RESET}"""


# ── helpers ────────────────────────────────────────────────────────────────────

def _read_file(filepath: str, max_bytes: int = None) -> bytes | None:
    """Read a file and return its bytes, or None on error."""
    try:
        with open(filepath, "rb") as fh:
            return fh.read(max_bytes) if max_bytes else fh.read()
    except OSError:
        return None


def _is_dotnet_umbral(filepath: str) -> bool:
    data = _read_file(filepath, 1024 * 512)
    return data is not None and is_umbral(data)

def _is_doenerium_file(filepath: str) -> bool:
    data = _read_file(filepath, 1024 * 512)
    return data is not None and is_doenerium(data)

def _is_stormkitty_file(filepath: str) -> bool:
    data = _read_file(filepath, 1024 * 512)
    return data is not None and is_stormkitty(data)

def _is_skuld_file(filepath: str) -> bool:
    # Full read — Go binaries can be 10 MB+
    data = _read_file(filepath)
    return data is not None and is_skuld(data)

def _is_xworm_file(filepath: str) -> bool:
    # Full read — XWorm stores config strings in the #US heap, past 512 KB
    data = _read_file(filepath)
    return data is not None and is_xworm(data)

def _is_quasar_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_quasar(data)

def _is_venomrat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_venomrat(data)

def _is_asyncrat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_asyncrat(data)

def _is_dcrat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_dcrat(data)

def _is_discordrat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_discordrat(data)

def _is_njrat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_njrat(data)

def _is_redline_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_redline(data)

def _is_limerat_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_limerat(data)

def _is_orcus_file(filepath: str) -> bool:
    data = _read_file(filepath)
    return data is not None and is_orcus(data)


# ── logging ────────────────────────────────────────────────────────────────────

def log(level: str, message: str):
    icons = {
        "info":    f"{CYAN}[*]{RESET}",
        "success": f"{GREEN}[+]{RESET}",
        "warn":    f"{YELLOW}[!]{RESET}",
        "error":   f"{RED}[-]{RESET}",
        "found":   f"{GREEN}[✓]{RESET}",
    }
    icon = icons.get(level, f"{WHITE}[?]{RESET}")
    print(f"  {icon} {message}")


# ── output ─────────────────────────────────────────────────────────────────────

def print_result_box(results: dict):
    """Pretty-print a bordered box with all found tokens/webhooks."""
    if not results:
        return

    has_c2 = any(k in results for k in ("webhook", "bot_token"))

    rows = []
    for k, v in results.items():
        if not v:
            continue
        if has_c2 and k in ("pyinstaller_version", "python_version"):
            continue
        if k == "type":
            label = "RAT" if v in _RAT_TYPES else _RESULT_LABELS["type"]
        else:
            label = _RESULT_LABELS.get(k, k.replace("_", " ").title())
        if isinstance(v, list):
            for item in v:
                rows.append((label, str(item)))
        else:
            rows.append((label, str(v)))

    if not rows:
        return

    inner_w = max(len(lbl) + 2 + len(val) for lbl, val in rows)
    inner_w = max(inner_w, 46)

    border = f"  {CYAN}\u250c{chr(0x2500) * (inner_w + 2)}\u2510{RESET}"
    sep    = f"  {CYAN}\u251c{chr(0x2500) * (inner_w + 2)}\u2524{RESET}"
    foot   = f"  {CYAN}\u2514{chr(0x2500) * (inner_w + 2)}\u2518{RESET}"

    print()
    print(border)
    title = "RESULTS"
    print(f"  {CYAN}\u2502 {WHITE}{title}{DIM}{' ' * (inner_w - len(title))} {RESET}{CYAN}\u2502{RESET}")
    print(sep)
    for label, val in rows:
        line = f"{YELLOW}{label}{RESET}  {WHITE}{val}{RESET}"
        visible = len(_ANSI_STRIP.sub("", line))
        pad = inner_w - visible
        print(f"  {CYAN}\u2502{RESET} {line}{' ' * pad} {CYAN}\u2502{RESET}")
    print(foot)
    print()


def prompt_action_discord(webhook_url: str, web: Webhook):
    while True:
        print(f"\n  {DIM}What do you want to do with this webhook?{RESET}")
        print(f"  {WHITE}[1]{RESET} Delete webhook")
        print(f"  {WHITE}[2]{RESET} Spam webhook")
        print(f"  {WHITE}[q]{RESET} Quit")
        choice = input(f"\n  {CYAN}→ {RESET}").strip().lower()
        if choice == "q":
            sys.exit(0)
        elif choice == "1":
            try:
                web.DeleteWebhook()
                log("success", "Webhook deleted.")
            except IOError as e:
                log("error", str(e))
            break
        elif choice == "2":
            i = 0
            while True:
                try:
                    web.SendWebhook()
                    i += 1
                    updateDisplayDiscord(i, web)
                    time.sleep(0.8)
                except IOError as e:
                    log("error", str(e))
                    break
        else:
            log("warn", "Invalid choice.")


# ── main ───────────────────────────────────────────────────────────────────────

def main():
    os.system("cls" if sys.platform == "win32" else "clear")
    print(ASCII_ART)

    # ── file input ─────────────────────────────────────────────────────────────
    print(f"  {DIM}Enter {WHITE}c{DIM} to view credits{RESET}")
    filepath = input(f"  {CYAN}Enter file path (or URL with -d prefix):{RESET} ").strip()

    if filepath.lower() == "c":
        print()
        inner_w = 46
        border = f"  {CYAN}\u250c{chr(0x2500) * (inner_w + 2)}\u2510{RESET}"
        sep    = f"  {CYAN}\u251c{chr(0x2500) * (inner_w + 2)}\u2524{RESET}"
        foot   = f"  {CYAN}\u2514{chr(0x2500) * (inner_w + 2)}\u2518{RESET}"
        print(border)
        title = "CREDITS"
        print(f"  {CYAN}\u2502 {WHITE}{title}{DIM}{' ' * (inner_w - len(title))} {RESET}{CYAN}\u2502{RESET}")
        print(sep)
        credit_line = f"{YELLOW}Author{RESET}  {WHITE}ryuka{RESET} {DIM}(n4pwo on discord){RESET}"
        visible = len(_ANSI_STRIP.sub("", credit_line))
        pad = inner_w - visible
        print(f"  {CYAN}\u2502{RESET} {credit_line}{' ' * pad} {CYAN}\u2502{RESET}")
        print(foot)
        print()
        sys.exit(0)

    download_mode = False
    if filepath.startswith("-d "):
        download_mode = True
        filepath = filepath[3:].strip()

    print()

    if download_mode:
        log("info", f"Downloading file from {filepath} ...")
        filepath = TryDownload(filepath)
        log("success", "File downloaded.")
    else:
        if not os.path.exists(filepath):
            log("error", "File does not exist.")
            sys.exit(1)

    filepath = os.path.abspath(filepath)
    log("info", f"Target: {WHITE}{filepath}{RESET}")

    if not exists(join(dirname(__file__), "temp")):
        os.makedirs(join(dirname(__file__), "temp"))

    results = {
        "type":                None,
        "webhook":             None,
        "bot_token":           None,
        "guild_id":            None,
        "pyinstaller_version": None,
        "python_version":      None,
    }

    found_value = None

    # ── java jar ───────────────────────────────────────────────────────────────
    if filepath.endswith(".jar"):
        log("info", "Java grabber suspected — scanning class strings...")
        javadir = unzipJava(filepath)
        ben = BenDeobf(javadir)
        found_value = ben.Deobfuscate()
        results["type"] = "java grabber"

    # ── Umbral Stealer (.NET) ──────────────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_dotnet_umbral(filepath):
        log("info", "Umbral Stealer (.NET binary) detected — scanning strings...")
        deobf = UmbralDeobf(filepath)
        found_value = deobf.Deobfuscate()
        results["type"] = "UmbralDeobf"
        if found_value:
            log("success", "Webhook found in .NET binary.")
        else:
            log("error", "Umbral binary confirmed but webhook not recovered.")

    # ── Doenerium (Electron / JS) ──────────────────────────────────────────────
    elif filepath.endswith((".exe", ".asar")) and _is_doenerium_file(filepath):
        log("info", "Doenerium (Electron/JS stealer) detected — extracting ASAR...")
        deobf = DoeneriumDeobf(filepath)
        found_value = deobf.Deobfuscate()
        results["type"] = "DoeneriumDeobf"
        if found_value:
            log("success", "Webhook found in ASAR bundle.")
        else:
            log("error", "Doenerium binary confirmed but webhook not recovered.")

    # ── StormKitty (.NET / Telegram) ──────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_stormkitty_file(filepath):
        log("info", "StormKitty (.NET stealer) detected — extracting C2 config...")
        deobf = StormKittyDeobf(filepath)
        found_value = deobf.Deobfuscate()
        results["type"] = "StormKittyDeobf"
        if found_value:
            log("success", "C2 config found.")
        else:
            log("error", "StormKitty binary confirmed but C2 config not recovered.")

    # ── Skuld Stealer (Go) ─────────────────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_skuld_file(filepath):
        log("info", "Skuld Stealer (Go binary) detected — scanning strings...")
        deobf = SkuldDeobf(filepath)
        found_value = deobf.Deobfuscate()
        results["type"] = "SkuldDeobf"
        if found_value:
            log("success", "Webhook found in Go binary.")
        else:
            log("error", "Skuld binary confirmed but webhook not recovered.")

    # ── XWorm RAT (.NET / TCP C2) ─────────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_xworm_file(filepath):
        log("warn", "XWorm RAT detected — C2 extraction not supported.")
        results["type"] = "XWorm RAT"

    # ── Quasar / Pulsar RAT (.NET) ────────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_quasar_file(filepath):
        log("warn", "Quasar/Pulsar RAT detected — C2 extraction not supported.")
        results["type"] = "Quasar/Pulsar RAT"

    # ── VenomRAT (.NET AsyncRAT fork) ────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_venomrat_file(filepath):
        log("warn", "VenomRAT detected — C2 extraction not supported.")
        results["type"] = "VenomRAT"

    # ── AsyncRAT (.NET) ───────────────────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_asyncrat_file(filepath):
        log("warn", "AsyncRAT detected — C2 extraction not supported.")
        results["type"] = "AsyncRAT"

    # ── DCRat / Dark Crystal RAT (.NET) ──────────────────────────────────────
    elif filepath.endswith(".exe") and _is_dcrat_file(filepath):
        log("warn", "DCRat detected — C2 extraction not supported.")
        results["type"] = "DCRat"

    # ── Discord RAT (.NET / Discord bot C2) ──────────────────────────────────
    elif filepath.endswith(".exe") and _is_discordrat_file(filepath):
        log("info", "Discord RAT detected — extracting bot token and guild ID...")
        results["type"] = "Discord RAT"
        with open(filepath, "rb") as _fh:
            _raw = _fh.read()
        _cfg = discordrat_extract_config(_raw)
        if _cfg.get("bot_token"):
            found_value = _cfg["bot_token"]
            log("found", "Discord bot token extracted from config.")
        else:
            log("warn", "Discord RAT detected but bot token could not be extracted.")
        if _cfg.get("guild_id"):
            results["guild_id"] = _cfg["guild_id"]
            log("found", f"Guild ID: {_cfg['guild_id']}")

    # ── NjRAT / Bladabindi (VB.NET) ──────────────────────────────────────────
    elif filepath.endswith(".exe") and _is_njrat_file(filepath):
        log("warn", "NjRAT/Bladabindi detected — C2 extraction not supported.")
        results["type"] = "NjRAT"

    # ── RedLine Stealer (.NET / WCF net.tcp C2) ──────────────────────────────
    elif filepath.endswith(".exe") and _is_redline_file(filepath):
        log("warn", "RedLine Stealer detected — C2 extraction not supported.")
        results["type"] = "RedLine Stealer"

    # ── LimeRAT (VB.NET / multi-feature RAT) ─────────────────────────────────
    elif filepath.endswith(".exe") and _is_limerat_file(filepath):
        log("warn", "LimeRAT detected — C2 extraction not supported.")
        results["type"] = "LimeRAT"

    # ── OrcusRAT (.NET C# commercial RAT) ────────────────────────────────────
    elif filepath.endswith(".exe") and _is_orcus_file(filepath):
        log("warn", "OrcusRAT detected — C2 extraction not supported.")
        results["type"] = "OrcusRAT"

    # ── PE / exe — attempt PyInstaller extraction ──────────────────────────────
    else:
        if checkUPX(filepath):
            log("warn", "File is UPX-packed — unpacking...")

        log("info", "Extracting PyInstaller archive...")
        try:
            archive = ExtractPYInstaller(filepath)
            ver = archive.pyinstVer or "?"
            pymaj = archive.pymaj or "?"
            pymin = archive.pymin or "?"
            results["pyinstaller_version"] = str(ver)
            results["python_version"] = f"{pymaj}.{pymin}"
            log("success", f"Extracted (PyInstaller {ver}, Python {pymaj}.{pymin})")
        except ExtractionError as e:
            log("error", "Not a PyInstaller archive or extraction failed.")
            sys.exit(1)

        extractiondir = os.getcwd()

        obfuscators = [
            BlankDeobf,
            LunaDeobf,
            VespyDeobf,
            ExelaDeobf,
            OtherDeobf,
            NotObfuscated,
        ]

        for deobfuscator in obfuscators:
            log("info", f"Trying method: {YELLOW}{deobfuscator.__name__}{RESET}")
            try:
                deobf = deobfuscator(extractiondir, archive.entrypoints)
                found_value = deobf.Deobfuscate()
                if found_value:
                    results["type"] = deobfuscator.__name__
                    log("success", f"Method matched: {deobfuscator.__name__}")
                    break
            except BlankVariantDetected as e:
                results["type"] = "BlankDeobf (variant — webhook not recovered)"
                log("warn", f"Blank grabber variant detected: {e}")
                log("info", "blank.aes present — confirmed Blank grabber, but webhook could not be extracted.")
                continue
            except Exception:
                log("warn", f"Method {deobfuscator.__name__} did not match — skipping.")
                continue

    # ── Go binary fallback — try Skuld if PyInstaller found nothing ──────────
    if not found_value and filepath.endswith(".exe"):
        try:
            with open(filepath, "rb") as _fh:
                _raw = _fh.read()
            if is_go_binary(_raw) and not results.get("type"):
                log("info", "No PyInstaller payload found — checking for Go stealer (Skuld)...")
                _wh = skuld_extract_webhook(_raw)
                if _wh:
                    found_value = _wh
                    results["type"] = "SkuldDeobf (fallback)"
                    log("success", "Webhook found in Go binary.")
        except OSError:
            pass

    if not found_value:
        if results.get("type"):
            _kind = "RAT" if results["type"] in _RAT_TYPES else "Grabber"
            log("warn", f"{_kind} identified but webhook/token could not be recovered.")
            print_result_box({k: v for k, v in results.items() if v})
            sys.exit(0)
        log("error", "No webhook or token found.")
        sys.exit(1)

    # ── classify what was found ────────────────────────────────────────────────
    if isinstance(found_value, str):
        candidates = [found_value]
    else:
        candidates = list(found_value)

    webhooks   = []
    bot_tokens = []
    telegram   = []

    TELEGRAM_PLAIN = re.compile(r"^[0-9]{8,12}:[a-zA-Z0-9_-]{35}$")
    DISCORD_WEBHOOK = re.compile(
        r"https://((ptb\.|canary\.|development\.)?)"
        r"discord(app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9\-_]{60,100}"
        r"(?=[^a-zA-Z0-9\-_]|$)"
    )

    for c in candidates:
        if DISCORD_WEBHOOK.match(c):
            webhooks.append(c)
        elif "$" in c:
            telegram.append(c)
        elif TELEGRAM_PLAIN.match(c):
            telegram.append(c + "$")
        elif BotToken.looks_like_bot_token(c):
            bot_tokens.append(c)
        else:
            log("warn", f"Unrecognised token format, skipping: {c[:80]}")

    # ── discord webhooks ───────────────────────────────────────────────────────
    for wh in webhooks:
        results["webhook"] = wh
        log("found", f"Discord webhook: {WHITE}{wh}{RESET}")
        web = Webhook(wh)
        try:
            valid = web.CheckValid(wh)
        except IOError as e:
            log("warn", f"Could not verify webhook (network error): {e}")
            log("info", "Webhook URL saved regardless.")
            continue
        if not valid:
            log("warn", "Webhook is invalid or deleted.")
        else:
            log("success", "Webhook is valid.")
            web.GetInformations()
            log("success", f"Webhook name: {web.name}")
            prompt_action_discord(wh, web)

    # ── discord bot tokens ─────────────────────────────────────────────────────
    for token in bot_tokens:
        results["bot_token"] = token
        log("found", f"Discord bot token: {WHITE}{token}{RESET}")
        bt = BotToken(token)
        try:
            info = bt.GetInformations()
            log("success", "Bot token is valid.")
            log("success", f"Bot username : {info.get('username', '?')}#{info.get('discriminator', '0')}")
            log("success", f"Bot ID       : {info.get('id', '?')}")
            log("success", f"Verified     : {info.get('verified', '?')}")
        except IOError as e:
            msg = str(e)
            if "401" in msg or "invalid or revoked" in msg.lower():
                log("warn", "Bot token is invalid or revoked.")
            else:
                log("warn", f"Could not verify bot token (network error): {e}")
                log("info", "Token saved regardless.")

    # ── telegram bot tokens ────────────────────────────────────────────────────
    for entry in telegram:
        token, chat_id = entry.split("$", 1)
        results["bot_token"] = token
        log("found", f"Telegram bot token: {WHITE}{token}{RESET}")
        try:
            if not Telegram.CheckValid(token):
                log("warn", "Telegram token is invalid or revoked.")
            else:
                log("success", "Telegram token is valid.")
                tg = Telegram(token)
                tg.GetInformations()
                log("success", f"Username        : @{tg.username}")
                log("success", f"First name      : {tg.firstName}")
                log("success", f"Can read groups : {tg.dump}")
        except Exception as e:
            log("warn", f"Could not verify Telegram token (network error): {e}")
            log("info", "Token saved regardless.")

    # ── summary box ────────────────────────────────────────────────────────────
    print_result_box({k: v for k, v in results.items() if v})

    if Webhook.GetDeleteConfig():
        shutil.rmtree(join(dirname(__file__), "temp"), ignore_errors=True)


if __name__ == "__main__":
    cfg = Config()
    main()