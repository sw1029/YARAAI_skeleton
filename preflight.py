import json
import os
from typing import Optional

from config import get_openai_api_key, CONFIG_PATH
from pipeline import process


def ensure_api_key() -> Optional[str]:
    key = get_openai_api_key()
    if key:
        print("OpenAI API key found.")
        return key
    print("OpenAI API key not configured.")
    user_key = input("Enter OpenAI API key (leave blank to skip): ").strip()
    if user_key:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({"openai_api_key": user_key}, f, indent=2)
        print("API key saved to config.json")
        return user_key
    print("Proceeding without API key.")
    return None


def check_input_file(path: str) -> bool:
    if not path:
        print("No input file provided.")
        return False
    if os.path.isfile(path):
        print(f"Found input file: {path}")
        return True
    print(f"Input file not found: {path}")
    return False


def run_test_pipeline(api_key: Optional[str]) -> None:
    sample = os.path.join(os.path.dirname(__file__), "sample.json")
    try:
        out_path = process(sample, openai_api_key=api_key, test_mode=True)
    except Exception as exc:
        print(f"Pipeline failed: {exc}")
        return
    if not out_path or not os.path.exists(out_path):
        print("Failed to generate YARA rule")
        return
    with open(out_path, "r", encoding="utf-8") as f:
        print(f"Generated YARA rule:\n{f.read()}")


def main() -> None:
    api_key = ensure_api_key()
    input_path = input("Path to executable or JSON file (optional): ").strip()
    check_input_file(input_path)

    run_test = input("Run pipeline in test mode? [y/N]: ").strip().lower().startswith("y")
    if run_test:
        run_test_pipeline(api_key)
    else:
        print("Preflight check complete.")


if __name__ == "__main__":
    main()
