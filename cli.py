import argparse
import os
import json
import re
import hashlib
import math
import zlib
from typing import Optional, Dict, List, Any

import pefile
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from config import get_openai_api_key
from pipeline import process


def _calc_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    length = len(data)
    for c in freq:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def _extract_strings(data: bytes) -> Dict[str, float]:
    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    if not strings:
        return {"string_count": 0, "avg_str_len": 0, "max_str_len": 0}
    lens = [len(s) for s in strings]
    return {
        "string_count": len(strings),
        "avg_str_len": sum(lens) / len(lens),
        "max_str_len": max(lens),
    }


def _disassemble(code: bytes, addr: int, arch: int) -> List[str]:
    md = Cs(CS_ARCH_X86, CS_MODE_64 if arch == 64 else CS_MODE_32)
    md.skipdata = True
    return [f"{i.mnemonic} {i.op_str}".strip() for i in md.disasm(code, addr)]


def preprocess_binary(path: str) -> str:
    """Analyze a binary executable and save extracted info as JSON."""

    with open(path, "rb") as f:
        raw = f.read()

    metadata: Dict[str, Any] = {
        "path": path,
        "module": os.path.basename(path),
        "filesize": os.path.getsize(path),
        "md5": hashlib.md5(raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "crc32": format(zlib.crc32(raw) & 0xFFFFFFFF, "08x"),
    }

    functions: List[Dict[str, Any]] = []
    current_addr = "0x0"

    if raw.startswith(b"MZ"):
        try:
            pe = pefile.PE(path)
            metadata["base"] = hex(pe.OPTIONAL_HEADER.ImageBase)
            metadata["size"] = hex(pe.OPTIONAL_HEADER.SizeOfImage)
            current_addr = hex(
                pe.OPTIONAL_HEADER.ImageBase
                + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            )
            arch = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
            text = next((s for s in pe.sections if b".text" in s.Name), None)
            if text:
                code = text.get_data()
                base_addr = pe.OPTIONAL_HEADER.ImageBase + text.VirtualAddress
                symbols = []
                if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                    symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols[:10]
                for idx, sym in enumerate(symbols):
                    name = sym.name.decode("utf-8", "ignore") if sym.name else f"func_{idx}"
                    addr = sym.address
                    offset = addr - base_addr
                    snippet = code[offset : offset + 64] if 0 <= offset < len(code) else b""
                    disasm = _disassemble(snippet, addr, arch)
                    functions.append({
                        "name": name,
                        "address": hex(addr),
                        "size": hex(len(snippet)),
                        "disassembly": disasm,
                    })
                if not functions:
                    for off in range(0, min(len(code), 0x100), 0x20):
                        addr = base_addr + off
                        snippet = code[off : off + 64]
                        disasm = _disassemble(snippet, addr, arch)
                        functions.append({
                            "name": f"func_{off:x}",
                            "address": hex(addr),
                            "size": hex(len(snippet)),
                            "disassembly": disasm,
                        })
        except Exception:
            pass
    elif raw.startswith(b"\x7fELF"):
        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                metadata["base"] = hex(elf.header["e_entry"])
                metadata["size"] = hex(os.path.getsize(path))
                current_addr = hex(elf.header["e_entry"])
                arch = 64 if elf.elfclass == 64 else 32
                text = elf.get_section_by_name(".text")
                if text:
                    code = text.data()
                    base_addr = text["sh_addr"]
                    symtab = elf.get_section_by_name(".symtab")
                    count = 0
                    if symtab:
                        for sym in symtab.iter_symbols():
                            if (
                                sym["st_info"]["type"] == "STT_FUNC"
                                and sym["st_size"] > 0
                                and base_addr <= sym["st_value"] < base_addr + len(code)
                            ):
                                offset = sym["st_value"] - base_addr
                                snippet = code[offset : offset + sym["st_size"]]
                                disasm = _disassemble(snippet, sym["st_value"], arch)
                                functions.append({
                                    "name": sym.name or f"func_{count}",
                                    "address": hex(sym["st_value"]),
                                    "size": hex(sym["st_size"]),
                                    "disassembly": disasm,
                                })
                                count += 1
                                if count >= 10:
                                    break
                    if not functions:
                        for off in range(0, min(len(code), 0x100), 0x20):
                            addr = base_addr + off
                            snippet = code[off : off + 64]
                            disasm = _disassemble(snippet, addr, arch)
                            functions.append({
                                "name": f"func_{off:x}",
                                "address": hex(addr),
                                "size": hex(len(snippet)),
                                "disassembly": disasm,
                            })
        except Exception:
            pass

    data = {
        "get_metadata": metadata,
        "get_current_address": current_addr,
        "file_entropy": _calc_entropy(raw),
        "string_stats": _extract_strings(raw),
        "functions": functions,
    }

    json_path = path + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
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
