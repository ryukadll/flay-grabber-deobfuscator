from os.path import join, dirname

import json
import requests
import time

from utils.config import Config

TIMEOUT = 10


class Webhook:
    def __init__(self, webhook):
        self.name = None
        self.config = Config.getConfig()
        self.webhook = webhook

    @staticmethod
    def CheckValid(webhook) -> bool:
        """
        Returns True if the webhook exists and responds with 200.
        Raises IOError on network failure so the caller can distinguish
        'definitely deleted' from 'could not reach Discord'.
        """
        try:
            r = requests.get(webhook, timeout=TIMEOUT)
            return r.status_code == 200
        except requests.exceptions.ConnectionError as e:
            raise IOError(f"Could not connect to Discord: {e}")
        except requests.exceptions.Timeout:
            raise IOError("Request timed out while checking webhook.")
        except requests.exceptions.RequestException as e:
            raise IOError(f"Request failed: {e}")

    def DeleteWebhook(self):
        if not self.CheckValid(self.webhook):
            raise IOError("Invalid Webhook")
        requests.post(self.webhook, headers={"Content-Type": "application/json"}, json=self.config["deletemessage"], timeout=TIMEOUT)
        requests.delete(self.webhook, timeout=TIMEOUT)

    def SendWebhook(self):
        if not self.CheckValid(self.webhook):
            raise IOError("Invalid webhook")
        r = requests.post(self.webhook, headers={"Content-Type": "application/json"}, json=self.config["spammessage"], timeout=TIMEOUT)
        match r.status_code:
            case 429:
                print("[-] Rate limited, waiting 5 seconds")
                time.sleep(5)
            case 404:
                print("[-] Webhook got deleted")
                quit(0)

    def GetInformations(self):
        r = requests.get(self.webhook, timeout=TIMEOUT)
        if r.status_code != 200:
            raise IOError("Invalid token")
        payload = r.json()
        self.name = payload["name"]

    @staticmethod
    def GetDeleteConfig():
        f = open(join(dirname(__file__), "..", "config.json"))
        config = json.loads(f.read())
        f.close()
        return config["deleteafterdeobf"]
