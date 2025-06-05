import os
from typing import Optional

from assembly_api import AssemblySummaryAPI
from data_maker import build_base_prompt, functions_to_asm, load_json
from model import YaraModel
from utils import parse_yara_rule, validate_yara_rule

# Explicit instruction appended to every prompt so the model
# returns a YARA rule in standard syntax.
YARA_PROMPT_SUFFIX = (
    "Using the information above, generate a YARA rule named `auto_generated`. "
    "The rule must include `meta`, `strings`, and `condition` sections and "
    "follow standard YARA syntax. Respond only with the rule in plain text, "
    "without any explanation."
)


ASM_DIR = "asm"
RESULT_DIR = "result"
RESPONSES_DIR = os.path.join(RESULT_DIR, "responses")


def process(json_path: str, openai_api_key: str, asm_api_url: Optional[str] = None) -> Optional[str]:
    data = load_json(json_path)
    base_prompt = build_base_prompt(data)

    asm_files = functions_to_asm(data, ASM_DIR)

    asm_api = AssemblySummaryAPI(asm_api_url)
    summaries = [asm_api.summarize(f) for f in asm_files]

    full_prompt = base_prompt
    if summaries:
        full_prompt += "\n\n" + "\n".join(summaries)
    # Ask explicitly for a YARA rule so the model doesn't return a summary
    full_prompt += "\n\n" + YARA_PROMPT_SUFFIX

    model = YaraModel(api_key=openai_api_key)
    os.makedirs(RESPONSES_DIR, exist_ok=True)
    for attempt in range(1, 4):
        try:
            response = model.generate_rule(full_prompt)
        except Exception as exc:  # Capture API errors
            response = f"Error during API call: {exc}"

        resp_path = os.path.join(RESPONSES_DIR, f"attempt_{attempt}.txt")
        with open(resp_path, "w", encoding="utf-8") as f:
            f.write(response)

        rule = parse_yara_rule(response)
        if rule and validate_yara_rule(rule):
            os.makedirs(RESULT_DIR, exist_ok=True)
            out_path = os.path.join(RESULT_DIR, "rule.yar")
            with open(out_path, "w", encoding="utf-8") as outf:
                outf.write(rule)
            return out_path

    raise RuntimeError("Failed to parse YARA rule after 3 attempts")


if __name__ == "__main__":
    import argparse
    from config import OPENAI_API_KEY

    parser = argparse.ArgumentParser(description="Generate YARA rule from json")
    parser.add_argument("json_path")
    parser.add_argument("--api_key", default=OPENAI_API_KEY)
    parser.add_argument("--asm_api")
    args = parser.parse_args()
    result = process(args.json_path, openai_api_key=args.api_key, asm_api_url=args.asm_api)
    if result:
        print(f"YARA rule saved to {result}")
    else:
        print("Failed to generate YARA rule")
