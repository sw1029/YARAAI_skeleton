import os
from typing import Optional

from assembly_api import AssemblySummaryClient
from config import get_openai_api_key
from data_maker import build_base_prompt, functions_to_asm, load_json
from model import YaraModel
from utils import parse_yara_rule, validate_yara_rule, check_false_positive_rate


ASM_DIR = "asm"
RESULT_DIR = "result"
RESPONSE_DIR = "responses"


def process(
    json_path: str,
    openai_api_key: Optional[str],
    asm_api_url: Optional[str] = None,
    test_mode: bool = False,
) -> Optional[str]:
    """Run the full pipeline for a given analysis json file.

    If ``test_mode`` is True, skip OpenAI calls and use a dummy YARA rule.
    """
    data = load_json(json_path)
    base_prompt = build_base_prompt(data)

    asm_files = functions_to_asm(data, ASM_DIR)

    asm_client = AssemblySummaryClient(api_url=asm_api_url)
    summaries = [asm_client.summarize(fp) for fp in asm_files]

    yara_request = (
        "\nGenerate a YARA rule in the following format:\n"
        "rule <name> {\n"
        "    strings:\n"
        "        <strings>\n"
        "    condition:\n"
        "        <condition>\n"
        "}"
    )
    full_prompt = base_prompt + "\n\n" + "\n".join(summaries) + yara_request

    if not test_mode and not openai_api_key:
        raise ValueError("OpenAI API key required unless test_mode is True")

    model = YaraModel(api_key=openai_api_key) if not test_mode else None
    os.makedirs(RESPONSE_DIR, exist_ok=True)
    rule = None
    for attempt in range(1, 4):
        if test_mode:
            response = "rule test_rule { strings: $a = \"dummy\" condition: $a }"
        else:
            response = model.generate_rule(full_prompt)
        resp_path = os.path.join(RESPONSE_DIR, f"response_{attempt}.txt")
        with open(resp_path, "w", encoding="utf-8") as f:
            f.write(response)
        parsed = parse_yara_rule(response)
        if not parsed:
            continue
        if not validate_yara_rule(parsed):
            continue
        fp_rate = check_false_positive_rate(parsed)
        if fp_rate > 0.1:
            continue
        rule = parsed
        break

    if rule is None:
        raise ValueError("Failed to parse YARA rule after 3 attempts")

    os.makedirs(RESULT_DIR, exist_ok=True)
    out_path = os.path.join(RESULT_DIR, "rule.yar")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(rule)
    return out_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate YARA rule from json")
    parser.add_argument("json_path", nargs="?")
    parser.add_argument("--asm_api")
    parser.add_argument("--test", action="store_true", help="run in offline test mode")
    args = parser.parse_args()

    if args.test or not args.json_path:
        sample_json = os.path.join(os.path.dirname(__file__), "sample.json")
        result = process(sample_json, openai_api_key=None, asm_api_url=args.asm_api, test_mode=True)
    else:
        api_key = get_openai_api_key()
        if not api_key:
            raise SystemExit("OpenAI API key not configured")

        result = process(args.json_path, openai_api_key=api_key, asm_api_url=args.asm_api)

    if result:
        print(f"YARA rule saved to {result}")
    else:
        print("Failed to generate YARA rule")
