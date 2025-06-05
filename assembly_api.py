from typing import Optional
import requests


class AssemblySummaryClient:
    """Wrapper for the external assembly summarization API."""

    def __init__(self, api_url: Optional[str] = None) -> None:
        self.api_url = api_url

    def summarize(self, asm_path: str) -> str:
        if not self.api_url:
            with open(asm_path, "r", encoding="utf-8") as f:
                content = f.read()
            return f"Summary for {asm_path}::\n" + content[:200]
        with open(asm_path, "r", encoding="utf-8") as f:
            files = {"file": f}
            response = requests.post(self.api_url, files=files, timeout=30)
        response.raise_for_status()
        return response.text.strip()
