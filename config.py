import json
import os
from typing import Any, Dict

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

def load_config(path: str = CONFIG_PATH) -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def get_openai_api_key(path: str = CONFIG_PATH) -> str:
    config = load_config(path)
    return config.get("openai_api_key", os.environ.get("OPENAI_API_KEY", ""))
