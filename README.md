# [flay](https://solution-flay.netlify.app/)

A static analysis tool for identifying and extracting C2 configuration from common grabbers and RATs. Point it at a suspicious binary and it will identify the malware family, extract webhooks or bot tokens where possible, and validate them live.

```
     ███████╗██╗      █████╗ ██╗   ██╗ 
     ██╔════╝██║     ██╔══██╗╚██╗ ██╔╝
     █████╗  ██║     ███████║ ╚████╔╝ 
     ██╔══╝  ██║     ██╔══██║  ╚██╔╝
     ██║     ███████╗██║  ██║   ██║ 
     ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝
                 grabber deobfuscator
```
 
---

## Features

- Identifies malware family from the binary alone, no execution required
- Extracts Discord webhooks, Discord bot tokens, and Telegram bot tokens where the format allows static recovery
- Validates extracted credentials live (checks if webhook/token is still active)
- Supports downloading samples directly via URL (`-d` prefix)
- PyInstaller extraction with automatic deobfuscation for Python-based grabbers

---

## Detection Coverage

### Stealers
| Family | Detection | C2 Extraction |
|---|---|---|
| Umbral Stealer | ✅ | ✅ Webhook |
| Doenerium | ✅ | ✅ Webhook |
| StormKitty | ✅ | ✅ Telegram token/Webhook |
| Skuld Stealer | ✅ | ✅ Webhook |
| RedLine Stealer | ✅ | ❌ |
| Blank Grabber | ✅ (via PyInstaller) | ✅ Webhook |
| Exela Stealer | ✅ (via PyInstaller) | ✅ Webhook |
| Luna Grabber | ✅ (via PyInstaller) | ✅ Webhook |
| Empyrean / Vespy | ✅ (via PyInstaller) | ✅ Webhook |
| Ben Grabber | ✅ (.jar) | ✅ Webhook |

### RATs
| Family | Detection | C2 Extraction |
|---|---|---|
| Discord RAT | ✅ | ✅ Bot token + Guild ID |
| XWorm | ✅ | ❌ |
| AsyncRAT | ✅ | ❌ |
| VenomRAT | ✅ | ❌ |
| DCRat | ✅ | ❌ |
| Quasar / Pulsar RAT | ✅ | ❌ |
| NjRAT / Bladabindi | ✅ | ❌ |
| LimeRAT | ✅ | ❌ |
| OrcusRAT | ✅ | ❌ |

---

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`

```
pip install -r requirements.txt
```

---

## Usage

```
python flay.py
```

You will be prompted for a file path or URL.

**Local file:**
```
Enter file path (or URL with -d prefix): C:\samples\malware.exe
```

**Download and analyse directly:**
```
Enter file path (or URL with -d prefix): -d https://example.com/sample.exe
```

---

## How it works

Detection uses a tiered fingerprint scoring system. Each binary is checked against family-specific string patterns (UTF-16LE for .NET, ASCII/Go string table for others) weighted by confidence:

- **HIGH** fingerprints: +3 — strings unique to a specific family's source
- **MEDIUM** fingerprints: +2 — strongly associated, rarely appear elsewhere  
- **LOW** fingerprints: +1 — present in the family but not uniquely identifying alone

A configurable threshold (default ≥5) must be reached before a family is declared. This avoids false positives from forks or shared code. Families that inherit code from others (e.g. VenomRAT from AsyncRAT) are checked first in the dispatcher.

For Python-based grabbers packed with PyInstaller, the archive is extracted and the embedded bytecode is decompiled before analysis.

---

## Notes

- Detection is static only — no sandboxing or dynamic analysis
- C2 extraction is only possible where credentials are stored in plaintext or with recoverable encoding. Encrypted configs (XWorm, AsyncRAT, etc.) are not extracted
- Extracted webhooks can optionally be deleted or spammed from within the tool

---

## Limitations

**flay only works reliably on unmodified or lightly modified samples.** Detection is based on known string fingerprints present in the original source. If a sample has been run through a custom crypter, packer, or obfuscator, the plaintext strings flay looks for will not be present in the binary, and detection will fail. This is expected behaviour, it is a fundamental constraint of static string-based analysis, not a bug.

**A clean result is not a clean bill of health.** If flay does not identify a file, that does not mean the file is safe. It means flay could not match it to a known family with confidence. The file may still be malicious, it could be an unknown family, a heavily modified variant, or something custom-built.

If flay draws a blank and you are still suspicious of a file, submit it to **[threat.rip](https://threat.rip)** for deeper analysis.


## Credits

- This project was heavily inspired by TaxMachine's [Grabbers-Deobfuscator](https://github.com/TaxMachine/Grabbers-Deobfuscator) and uncoverit.org
