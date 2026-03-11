import re
import requests

# Discord bot tokens: base64(user_id).timestamp_b64.hmac
BOT_TOKEN_REGEX = r"([MN][A-Za-z0-9]{23,26}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,45})(?=[^A-Za-z0-9_-]|$)"

DISCORD_API = "https://discord.com/api/v10"
TIMEOUT = 10


class BotToken:
    def __init__(self, token: str):
        self.token = token.strip()

    @staticmethod
    def looks_like_bot_token(value: str) -> bool:
        return bool(re.fullmatch(BOT_TOKEN_REGEX, value.strip()))

    def CheckValid(self) -> bool:
        """
        Returns True if Discord accepts the token.
        Raises IOError on network failure so caller can distinguish
        connection problems from a genuinely invalid/revoked token.
        """
        try:
            r = requests.get(
                f"{DISCORD_API}/users/@me",
                headers={"Authorization": f"Bot {self.token}"},
                timeout=TIMEOUT
            )
            return r.status_code == 200
        except requests.exceptions.ConnectionError as e:
            raise IOError(f"Could not connect to Discord: {e}")
        except requests.exceptions.Timeout:
            raise IOError("Request timed out while checking bot token.")
        except requests.exceptions.RequestException as e:
            raise IOError(f"Request failed: {e}")

    def GetInformations(self) -> dict:
        """
        Fetches bot info from Discord API.
        Raises IOError on network failure or invalid token.
        Returns the parsed JSON dict on success.
        """
        try:
            r = requests.get(
                f"{DISCORD_API}/users/@me",
                headers={"Authorization": f"Bot {self.token}"},
                timeout=TIMEOUT
            )
        except requests.exceptions.ConnectionError as e:
            raise IOError(f"Could not connect to Discord: {e}")
        except requests.exceptions.Timeout:
            raise IOError("Request timed out while fetching bot info.")
        except requests.exceptions.RequestException as e:
            raise IOError(f"Request failed: {e}")

        if r.status_code == 401:
            raise IOError("Bot token is invalid or revoked (401 Unauthorized).")
        if r.status_code == 403:
            raise IOError("Bot token forbidden (403).")
        if r.status_code != 200:
            raise IOError(f"Unexpected response from Discord: HTTP {r.status_code}")

        return r.json()
