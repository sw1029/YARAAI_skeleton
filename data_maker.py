import json
import os
from typing import Dict, List


def load_json(path: str) -> Dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def build_base_prompt(data: Dict) -> str:
    parts: List[str] = []
    metadata = data.get('get_metadata')
    if metadata:
        parts.append(f"metadata: {metadata}")

    current_addr = data.get('get_current_address')
    if current_addr:
        parts.append(f"current_address: {current_addr}")

    entropy = data.get('file_entropy')
    if entropy is not None:
        parts.append(f"entropy: {entropy}")

    string_stats = data.get('string_stats')
    if string_stats:
        parts.append(f"string_stats: {string_stats}")

    return '\n'.join(parts)


def functions_to_asm(data: Dict, out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths: List[str] = []
    for fn in data.get('functions', []):
        name = fn.get('name', 'func')
        asm_path = os.path.join(out_dir, f"{name}.asm")
        with open(asm_path, 'w', encoding='utf-8') as f:
            disasm = fn.get('disassembly', [])
            if isinstance(disasm, list):
                f.write('\n'.join(disasm))
            else:
                f.write(str(disasm))
        paths.append(asm_path)
    return paths


def binary_to_json(binary_path: str, json_out: str) -> str:
    """Convert binary file to expected JSON format.

    This is a stub implementation. In practice, this should parse the binary
    using a disassembler and output JSON with metadata and functions.
    """
    # TODO: implement real binary parsing logic
    data = {
        "get_metadata": {"path": binary_path},
        "functions": []
    }
    with open(json_out, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return json_out
