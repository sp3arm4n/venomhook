# -*- coding: utf-8 -*-
#@category VenomHook
"""
Ghidra postScript to export StaticMeta JSON for venomhook.
Usage (headless):
  analyzeHeadless <projectDir> <projectName> -import <binary> -overwrite \
    -scriptPath <ghidra_scripts full path> \
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

def safe_hex(x):
    try:
        return hex(int(x)).replace("L", "")
    except:
        return hex(int(x & 0xFFFFFFFFFFFFFFFF)).replace("L", "")

def main():
    args = getScriptArgs()
    if args is None or len(args) < 1:
        print("Usage: export_staticmeta.py <out_json>")
        return

    out_path = args[0]
    try:
        prog = currentProgram
    except NameError:
        print("ERROR: currentProgram is not defined. Are you running this via Ghidra headless (-postScript)?")
        return

    if prog is None:
        print("ERROR: currentProgram is None. Failed to load target program in Ghidra.")
        return
    image_base = get_image_base(prog)

    funcs = []
    fm = prog.getFunctionManager()
    listing = prog.getListing()
    binary_path = prog.getExecutablePath()
    if binary_path and os.path.exists(binary_path):
        binary_hash = compute_sha256(binary_path)
    else:
        binary_hash = ""
        binary_path = ""

    try:
        monitor.setMessage("Collecting functions...")
    except NameError:
        # headless 환경에 따라 monitor가 없을 수도 있으므로 강제 실패시키지 않고 경고만 출력
        print("WARNING: monitor object is not available. Continuing without progress messages.")
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
            sym = prog.getSymbolTable().getPrimarySymbol(to_addr)
            if sym and sym.getSymbolType().toString() == "LIBRARY":
                callees.append({"type": "import", "name": sym.getName()})
            else:
                callees.append({"type": "local", "rva": to_addr.getOffset() - image_base})

        # Strings near function (limit)
        fn_strings = []
        body = func.getBody()
        if body is None:
            continue

        it = listing.getDefinedData(body, True)
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
        try:
            inst = listing.getCodeUnitAt(entry)
            if inst is not None:
                max_len = 16
                bs = inst.getBytes()
                if bs:
                    raw_bytes = " ".join("{:02X}".format(b & 0xFF) for b in bs[:max_len])
        except Exception as e:
            # raw_bytes 수집 실패는 치명적이지 않으므로 그냥 넘어감
            # print("WARNING: failed to read raw bytes at entry: {}".format(e))
            pass

        funcs.append(
            {
                "va": safe_hex(va),
                "rva": safe_hex(rva),
                "name": func.getName(),
                "size": func.getBody().getNumAddresses(),
                "basic_blocks": bb_count,
                "callers": [safe_hex(c) for c in callers],
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
        fp = open(out_path, "w")
        fp.write(json.dumps(payload, indent=2))
        fp.close()
        print("Wrote StaticMeta to {}".format(out_path))
    except Exception as e:
        print("Failed to write StaticMeta: {}".format(e))



if __name__ == "__main__":
    main()
