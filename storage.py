import json
import os
from typing import Dict, Any


def ensure_directories():
    os.makedirs("certs", exist_ok=True)
    os.makedirs("data", exist_ok=True)


def save_json(path: str, obj: Dict[str, Any]):
    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

        if not content:
            return {}

        return json.loads(content)


def load_json_or_empty(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}

    return load_json(path)