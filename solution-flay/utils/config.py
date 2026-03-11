import json
from os.path import dirname, exists, join

_DEFAULTS = {
    "deletemessage": {
        "content": "@everyone",
        "embeds": [
            {
                "title": "flay",
                "description": "webhook nuked.",
                "color": 0x5865F2
            }
        ]
    },
    "spammessage": {
        "content": "@everyone",
        "embeds": [
            {
                "title": "flay",
                "description": ".",
                "color": 0x5865F2
            }
        ]
    },
    "deleteafterdeobf": True,
    "telegram_message": "flay"
}


class Config:
    def __init__(self):
        cfg_path = join(dirname(__file__), "..", "config.json")
        if not exists(cfg_path):
            with open(cfg_path, "w") as f:
                f.write(json.dumps(_DEFAULTS, indent=4))

    @staticmethod
    def getConfig() -> dict:
        cfg_path = join(dirname(__file__), "..", "config.json")
        if not exists(cfg_path):
            return _DEFAULTS
        with open(cfg_path) as f:
            return json.loads(f.read())
