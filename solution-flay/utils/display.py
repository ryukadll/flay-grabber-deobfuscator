import os
import sys

from utils.telegram import Telegram
from utils.webhookspammer import Webhook

CYAN  = "\033[96m"
WHITE = "\033[97m"
GREEN = "\033[92m"
RESET = "\033[0m"


def _clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def updateDisplayDiscord(index: int, discord: Webhook):
    _clear()
    print(f"""
{CYAN}  ┌──────────────────────────────────────────────┐
  │  flay  ·  webhook spammer                    │
  ├──────────────────────────────────────────────┤
  │  Webhook   {WHITE}{discord.name:<34}{CYAN}│
  ├──────────────────────────────────────────────┤
  │  Spammed   {GREEN}{str(index):<34}{CYAN}│
  └──────────────────────────────────────────────┘{RESET}
""")


def updateDisplayTelegram(index: int, telegram: Telegram):
    _clear()
    print(f"""
{CYAN}  ┌──────────────────────────────────────────────┐
  │  flay  ·  telegram spammer                   │
  ├──────────────────────────────────────────────┤
  │  Username   {WHITE}@{telegram.username:<33}{CYAN}│
  │  Name       {WHITE}{telegram.firstName:<34}{CYAN}│
  │  Read msgs  {WHITE}{str(telegram.dump):<34}{CYAN}│
  ├──────────────────────────────────────────────┤
  │  Spammed    {GREEN}{str(index):<34}{CYAN}│
  └──────────────────────────────────────────────┘{RESET}
""")
