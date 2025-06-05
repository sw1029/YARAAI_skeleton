import argparse
import os
from typing import Optional

from config import get_openai_api_key
from pipeline import process


def preprocess_binary(path: str) -> str:
    """Convert an executable to json. Placeholder implementation."""
    # TODO: integrate real preprocessing logic
    json_path = path + ".json"
    if not os.path.exists(json_path):
        with open(json_path, "w", encoding="utf-8") as f:
            f.write("{}")
    return json_path


def run_pipeline(input_path: str, asm_api: Optional[str], test_mode: bool = False) -> None:
    if input_path.lower().endswith(".json"):
        json_path = input_path
    else:
        json_path = preprocess_binary(input_path)

    api_key = get_openai_api_key()
    if not api_key and not test_mode:
        raise SystemExit("OpenAI API key not configured")

    result = process(
        json_path,
        openai_api_key=api_key,
        asm_api_url=asm_api,
        test_mode=test_mode,
    )
    if result:
        print(f"YARA rule saved to {result}")
    else:
        print("Failed to generate YARA rule")


def main() -> None:
    parser = argparse.ArgumentParser(description="YARA rule generation CLI")
    parser.add_argument("input_path", nargs="?")
    parser.add_argument("--asm_api")
    parser.add_argument("--test", action="store_true", help="run in offline test mode")
    args = parser.parse_args()

    if args.test or not args.input_path:
        sample_json = os.path.join(os.path.dirname(__file__), "sample.json")
        run_pipeline(sample_json, args.asm_api, test_mode=True)
    else:
        run_pipeline(args.input_path, args.asm_api)


if __name__ == "__main__":
    main()
