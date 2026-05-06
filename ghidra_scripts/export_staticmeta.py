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

def is_external_addr(prog, addr):
    block = prog.getMemory().getBlock(addr)
    if block is None:
        return False
    try:
        return block.isExternalBlock()
    except:
        return block.getName() == "EXTERNAL"

def is_call_ref(ref):
    try:
        return ref.getReferenceType().isCall()
    except:
        return "call" in str(ref.getReferenceType()).lower()

def iter_body_refs(prog, body):
    refman = prog.getReferenceManager()
    addr_it = body.getAddresses(True)
    while addr_it.hasNext():
        addr = addr_it.next()
        refs = refman.getReferencesFrom(addr)
        for ref in refs:
            yield ref

def get_symbol_name(sym):
    if sym is None:
        return None
    try:
        return sym.getName()
    except:
        try:
            return sym.getName(True)
        except:
            return None

def get_import_name(prog, addr):
    sym = prog.getSymbolTable().getPrimarySymbol(addr)
    if sym is not None:
        try:
            if sym.isExternal():
                return get_symbol_name(sym)
        except:
            pass
        if is_external_addr(prog, addr):
            return get_symbol_name(sym)

    func = prog.getFunctionManager().getFunctionAt(addr)
    if func is None:
        return None
    try:
        if func.isExternal():
            return func.getName()
    except:
        pass
    try:
        thunked = func.getThunkedFunction(True)
        if thunked is not None:
            return thunked.getName()
    except:
        pass
    try:
        if func.isThunk():
            return func.getName()
    except:
        pass
    return None

def get_string_at(prog, addr):
    listing = prog.getListing()
    data = None
    try:
        data = listing.getDataAt(addr)
    except:
        data = None
    if data is None:
        try:
            data = listing.getDefinedDataContaining(addr)
        except:
            data = None
    if data is not None:
        try:
            if data.hasStringValue():
                s = str(data.getValue()).strip()
                if len(s) > 2:
                    return s
        except:
            pass
    return None

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

        # Callees/imports and referenced strings. Inspect references from the
        # whole function body, not only the entry instruction; most interesting
        # API calls and string xrefs appear after the prologue.
        callees = []
        seen_callees = set()
        fn_strings = []
        seen_strings = set()
        body = func.getBody()
        if body is None:
            continue

        for ref in iter_body_refs(prog, body):
            to_addr = ref.getToAddress()
            s = get_string_at(prog, to_addr)
            if s and s not in seen_strings and len(fn_strings) < 10:
                fn_strings.append(s)
                seen_strings.add(s)

            if not is_call_ref(ref):
                continue

            import_name = get_import_name(prog, to_addr)
            if import_name:
                key = ("import", import_name)
                if key not in seen_callees:
                    callees.append({"type": "import", "name": import_name})
                    seen_callees.add(key)
                continue

            if is_executable_addr(prog, to_addr):
                local_rva = to_addr.getOffset() - image_base
                key = ("local", local_rva)
                if key not in seen_callees:
                    callees.append({"type": "local", "rva": local_rva})
                    seen_callees.add(key)

        # Inline strings defined inside the function body are uncommon but cheap
        # to retain as a fallback alongside xref-derived strings.
        it = listing.getDefinedData(body, True)
        while it.hasNext() and len(fn_strings) < 10:
            data = it.next()
            if data.hasStringValue():
                s = str(data.getValue()).strip()
                if len(s) > 2 and s not in seen_strings:
                    fn_strings.append(s)
                    seen_strings.add(s)

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
        "image_base": safe_hex(image_base),
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
