# -*- coding: utf-8 -*-
#@category Vahana
"""
Ghidra postScript to export StaticMeta JSON for venomhook.
Usage (headless):
  ghidraRun <projectDir> <projectName> -import <binary> -overwrite \
    -postScript export_staticmeta.py /path/to/out_staticmeta.json

Writes a JSON with binary info and a subset of function metadata (VA, RVA, name,
basic block count, callers, callees/imports, strings, raw bytes prefix).
"""

import hashlib
import json
import os
import sys

from ghidra.program.model.symbol import SymbolType


def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(8192), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def get_image_base(current_program):
    return current_program.getImageBase().getOffset()


def get_strings(current_program, limit=2000):
    listing = current_program.getListing()
    strings = []
    for data in listing.getDefinedData(True):
        if data.hasStringValue():
            s = str(data.getValue()).strip()
            if len(s) > 2:
                strings.append((data.getMinAddress().getOffset(), s))
    return strings[:limit]


def is_executable_addr(prog, addr):
    block = prog.getMemory().getBlock(addr)
    return block is not None and block.isExecute()


def main():
    if len(sys.argv) < 2:
        print("Usage: export_staticmeta.py <out_json>")
        return
    out_path = sys.argv[1]
    prog = currentProgram
    image_base = get_image_base(prog)

    funcs = []
    fm = prog.getFunctionManager()
    listing = prog.getListing()
    binary_path = prog.getExecutablePath()
    binary_hash = compute_sha256(binary_path) if os.path.exists(binary_path) else ""

    monitor.setMessage("Collecting functions...")
    for func in fm.getFunctions(True):
        if func.isExternal():
            continue
        entry = func.getEntryPoint()
        if not is_executable_addr(prog, entry):
            continue
        name = func.getName()
        # 간단한 필터: 너무 작은 함수/의미 없는 이름 스킵
        if func.getBody().getNumAddresses() < 4:
            continue
        if name.startswith("FUN_") and func.getBody().getNumAddresses() < 8:
            continue

        va = entry.getOffset()
        rva = va - image_base
        bb_count = func.getBody().getNumAddresses()

        # Callers
        callers = []
        refs_to = prog.getReferenceManager().getReferencesTo(entry)
        for ref in refs_to:
            callers.append(ref.getFromAddress().getOffset())

        # Callees/imports
        callees = []
        for ref in prog.getReferenceManager().getReferencesFrom(entry):
            to_addr = ref.getToAddress()
            sym = prog.getSymbolTable().getSymbolAt(to_addr)
            if sym and sym.getSymbolType() == SymbolType.LIBRARY:
                callees.append({"type": "import", "name": sym.getName()})
            else:
                callees.append({"type": "local", "rva": to_addr.getOffset() - image_base})

        # Strings near function (limit)
        fn_strings = []
        body = func.getBody()
        it = listing.getData(body, True)
        while it.hasNext() and len(fn_strings) < 10:
            data = it.next()
            if data.hasStringValue():
                s = str(data.getValue()).strip()
                if len(s) > 2:
                    fn_strings.append(s)

        # Imports called (symbol names)
        imports = [c["name"] for c in callees if c.get("type") == "import"]

        # Raw bytes prefix (instruction bytes at entry)
        inst = listing.getCodeUnitAt(entry)
        raw_bytes = None
        if inst:
            max_len = 16
            bs = inst.getBytes()
            if bs:
                raw_bytes = " ".join("{:02X}".format(b & 0xFF) for b in bs[:max_len])

        funcs.append(
            {
                "va": hex(va),
                "rva": hex(rva),
                "name": func.getName(),
                "size": func.getBody().getNumAddresses(),
                "basic_blocks": bb_count,
                "callers": [hex(c) for c in callers],
                "callees": callees,
                "strings": fn_strings[:10],
                "imports": imports,
                "raw_bytes": raw_bytes,
            }
        )

    binary_info = {
        "name": os.path.basename(binary_path),
        "hash": binary_hash,
        "arch": prog.getLanguage().getProcessor().toString(),
        "image_base": hex(image_base),
    }

    payload = {"binary": binary_info, "functions": funcs}
    try:
        with open(out_path, "w", encoding="utf-8") as fp:
            json.dump(payload, fp, indent=2)
        print(f"Wrote StaticMeta to {out_path}")
    except Exception as e:
        print(f"Failed to write StaticMeta: {e}")


if __name__ == "__main__":
    main()
