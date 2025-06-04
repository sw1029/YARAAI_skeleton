import os
from typing import Optional

from data_maker import build_base_prompt, functions_to_asm, load_json
from model import YaraModel
from utils import parse_yara_rule, summarize_assembly, validate_yara_rule


ASM_DIR = "asm"
RESULT_DIR = "result"


def process(json_path: str, openai_api_key: str, asm_api_url: Optional[str] = None) -> Optional[str]:
    data = load_json(json_path)
    base_prompt = build_base_prompt(data)

    asm_files = functions_to_asm(data, ASM_DIR)

    summaries = []
    for asm_file in asm_files:
        summaries.append(summarize_assembly(asm_file, asm_api_url))

    full_prompt = base_prompt + "\n\n" + "\n".join(summaries)

    model = YaraModel(api_key=openai_api_key)
    response = model.generate_rule(full_prompt)
    rule = parse_yara_rule(response)
    if not rule:
        return None

    if not validate_yara_rule(rule):
        return None

    os.makedirs(RESULT_DIR, exist_ok=True)
    out_path = os.path.join(RESULT_DIR, "rule.yar")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rule)
    return out_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate YARA rule from json")
    parser.add_argument("json_path")
    parser.add_argument("--api_key", required=True)
    parser.add_argument("--asm_api")
    args = parser.parse_args()
    result = process(args.json_path, openai_api_key=args.api_key, asm_api_url=args.asm_api)
    if result:
        print(f"YARA rule saved to {result}")
    else:
        print("Failed to generate YARA rule")
