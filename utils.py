import json
import os
import re
from typing import Any, Dict, List, Optional

import requests
import yara
import openai


def summarize_assembly(asm_path: str, api_url: Optional[str] = None) -> str:
    """Return a natural language summary for a given assembly file."""
    if api_url is None:
        # Stub summary if no API is provided
        with open(asm_path, "r", encoding="utf-8") as f:
            asm_content = f.read()
        return f"Summary for {os.path.basename(asm_path)}:\n" + asm_content[:200]

    with open(asm_path, "r", encoding="utf-8") as f:
        files = {"file": f}
        response = requests.post(api_url, files=files, timeout=30)
    response.raise_for_status()
    return response.text.strip()


def call_openai_api(prompt: str, api_key: str, model: str = "gpt-4.1") -> str:
    """Call OpenAI chat completion API and return response text."""
    openai.api_key = api_key
    completion = openai.ChatCompletion.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return completion.choices[0].message["content"].strip()


def parse_yara_rule(text: str) -> Optional[str]:
    """Extract the first YARA rule from text with balanced braces."""
    start_match = re.search(r"rule\s+\w+\s*\{", text)
    if not start_match:
        return None

    start = start_match.start()
    brace_count = 0
    for i in range(start, len(text)):
        if text[i] == '{':
            brace_count += 1
        elif text[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                return text[start:i + 1]
    return None


def validate_yara_rule(rule_str: str) -> bool:
    """Validate YARA rule by compiling it."""
    try:
        yara.compile(source=rule_str)
        return True
    except yara.Error:
        return False
