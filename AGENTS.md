# Agent Instructions

The agent is responsible for composing prompts that lead to YARA rule generation and validating the generated rules.

- Use `gpt-4.1` model when calling the OpenAI API.
- Always append a request for a YARA rule at the end of prompts.
- Validate rules with `validate_yara_rule` before saving.
- API keys must be loaded from `config.json` or environment variables using `get_openai_api_key`.
