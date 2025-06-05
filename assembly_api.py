from typing import Optional
import requests

from utils import call_openai_api


class AssemblySummaryClient:
    """Wrapper for assembly summarization using an API or OpenAI."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        openai_api_key: Optional[str] = None,
        openai_model: str = "gpt-4o",
    ) -> None:
        self.api_url = api_url
        self.openai_api_key = openai_api_key
        self.openai_model = openai_model

    def summarize(self, asm_path: str) -> str:
        """Return a natural language summary for a single assembly file."""
        if self.api_url:
            with open(asm_path, "r", encoding="utf-8") as f:
                files = {"file": f}
                response = requests.post(self.api_url, files=files, timeout=30)
            response.raise_for_status()
            return response.text.strip()

        if self.openai_api_key:
            with open(asm_path, "r", encoding="utf-8") as f:
                content = f.read()
            max_chars = 8000
            if len(content) > max_chars:
                content = content[:max_chars]
            prompt = (
                "Summarize the following assembly code in a short sentence:\n\n" + content
            )
            return call_openai_api(
                prompt, api_key=self.openai_api_key, model=self.openai_model
            )

        with open(asm_path, "r", encoding="utf-8") as f:
            content = f.read()
        return f"Summary for {asm_path}::\n" + content[:200]
