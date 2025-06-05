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
    client = openai.OpenAI(api_key=api_key)
    completion = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
    )
    return completion.choices[0].message.content.strip()


def parse_yara_rule(text: str) -> Optional[str]:
    """Extract the first YARA rule from text.

    The function first checks fenced code blocks and falls back to a
    simple regex search. This helps handle responses that include
    additional commentary or Markdown formatting.
    """
    # Look for a rule inside fenced code blocks first
    fence = re.search(
        r"```(?:yara|text)?\n(?P<rule>rule\s+\w+\s*\{[\s\S]*?\})\n```",
        text,
        re.IGNORECASE,
    )
    if fence:
        return fence.group("rule").strip()

    # Fallback: search anywhere in the text. Use a greedy match so nested
    # braces in hex strings do not truncate the rule.
    match = re.search(r"rule\s+\w+\s*\{[\s\S]*\}", text, re.IGNORECASE)
    return match.group(0).strip() if match else None


def validate_yara_rule(rule_str: str) -> bool:
    """Validate YARA rule by compiling it."""
    try:
        yara.compile(source=rule_str)
        return True
    except yara.Error:
        return False


def false_positive_rate(rule_str: str, sample_paths: List[str]) -> float:
    """Return false positive rate for the rule across given sample files."""
    compiled = yara.compile(source=rule_str)
    total = len(sample_paths)
    if total == 0:
        return 0.0
    hits = 0
    for path in sample_paths:
        try:
            matches = compiled.match(filepath=path)
            if matches:
                hits += 1
        except Exception:
            # Ignore files that cannot be scanned
            pass
    return hits / total
