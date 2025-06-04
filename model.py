from typing import Optional

from utils import call_openai_api


class YaraModel:
    """Wrapper for generating YARA rules using OpenAI."""

    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo") -> None:
        self.api_key = api_key
        self.model = model

    def generate_rule(self, prompt: str) -> str:
        return call_openai_api(prompt, api_key=self.api_key, model=self.model)
