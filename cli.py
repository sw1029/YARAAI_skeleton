import argparse
import os
from typing import List

from assembly_api import AssemblySummaryAPI
from config import OPENAI_API_KEY
from data_maker import binary_to_json
from pipeline import process


def collect_samples(directory: str) -> List[str]:
    paths = []
    for root, _, files in os.walk(directory):
        for name in files:
            paths.append(os.path.join(root, name))
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="YARA rule generation CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate rule from file")
    gen.add_argument("path", help="Input JSON or binary file")
    gen.add_argument("--asm_api")
    gen.add_argument("--samples", help="Directory of benign samples for FP check")

    args = parser.parse_args()

    if args.command == "generate":
        input_path = args.path
        if input_path.lower().endswith((".json")):
            json_path = input_path
        elif input_path.lower().endswith((".exe", ".dll")):
            json_path = os.path.join("tmp", os.path.basename(input_path) + ".json")
            os.makedirs("tmp", exist_ok=True)
            json_path = binary_to_json(input_path, json_path)
        else:
            parser.error("Unsupported file type")

        asm_api = AssemblySummaryAPI(args.asm_api)
        try:
            result = process(json_path, OPENAI_API_KEY, asm_api_url=args.asm_api)
        except Exception as exc:
            print(f"Error: {exc}")
            result = None

        if result:
            print(f"YARA rule saved to {result}")
            if args.samples:
                from utils import false_positive_rate
                sample_paths = collect_samples(args.samples)
                with open(result, "r", encoding="utf-8") as f:
                    rule = f.read()
                rate = false_positive_rate(rule, sample_paths)
                print(f"False positive rate: {rate:.2%}")
        else:
            print("Failed to generate YARA rule")


if __name__ == "__main__":
    main()
