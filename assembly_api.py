import os
from typing import Optional

import requests


class AssemblySummaryAPI:
    """Wrapper for an assembly summary web API."""

    def __init__(self, url: Optional[str] = None) -> None:
        self.url = url

    def summarize(self, asm_path: str) -> str:
        if self.url is None:
            with open(asm_path, "r", encoding="utf-8") as f:
                content = f.read()
            return f"Summary for {os.path.basename(asm_path)}:\n" + content[:200]
        with open(asm_path, "rb") as f:
            response = requests.post(self.url, files={"file": f}, timeout=30)
        response.raise_for_status()
        return response.text.strip()
