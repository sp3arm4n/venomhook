from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from venomhook.models import HookSpec
from venomhook.store import HookSpecStore


def _js_str(value: str | None) -> str:
    """Encode a Python string as a safe JS string literal (handles quotes/backslashes/newlines)."""
    return json.dumps(value if value is not None else "")


class DynamicPipeline:
    def __init__(
        self,
        target: str,
        log_format: str = "text",
        log_prefix: str = "[venomhook]",
        scenario_message: str | None = None,
        auto_start_scenario: bool = False,
        hexdump_len: int = 64,
        string_args: list[int] | None = None,
        string_ret: bool = False,
        string_len: int = 128,
        scan_size: int | None = None,
        retry_attach: int = 1,
    ):
        self.target = target
        self.log_format = log_format
        self.log_prefix = log_prefix
        self.scenario_message = scenario_message
        self.auto_start_scenario = auto_start_scenario
        self.hexdump_len = hexdump_len
        self.string_args = string_args or []
        self.string_ret = string_ret
        self.string_len = string_len
        self.scan_size = scan_size
        self.retry_attach = retry_attach if retry_attach > 0 else 1

    def generate_script(self, specs: Iterable[HookSpec]) -> str:
        hooks = list(specs)
        blocks = [self._render_hook_block(spec) for spec in hooks]
        calls = [f"hook_{self._safe_name(spec)}();" for spec in hooks]
        scenario_block: list[str] = []
        if self.scenario_message:
            scenario_block = [
                "",
                "function runScenario() { send({type: \"scenario\", message: "
                + _js_str(self.scenario_message)
                + "}); }",
            ]
        main_calls = ["  " + call for call in calls]
        if self.scenario_message and self.auto_start_scenario:
            main_calls.append("  runScenario();")

        # Comment line — sanitize newlines so JS comment doesn't break
        target_for_comment = (self.target or "").replace("\n", " ").replace("\r", " ")

        return "\n".join(
            [
                "// Auto-generated Frida script",
                f"// target: {target_for_comment}",
                "",
                f"const LOG_FORMAT = {_js_str(self.log_format)};",
                f"const LOG_PREFIX = {_js_str(self.log_prefix)};",
                "const ptrToHex = function (ptrVal) {",
                "  return ptrVal ? ptrVal.toString(16) : '0x0';",
                "};",
                "",
                f"const HEXDUMP_LEN = {self.hexdump_len};",
                f"const STRING_LEN = {self.string_len};",
                f"const SCAN_SIZE = {self.scan_size if self.scan_size else 0};",
                f"const RETRY_ATTACH = {self.retry_attach};",
                "const hookStats = {};",
                "function logEvent(event, hook, detail) {",
                "  if (LOG_FORMAT === 'json') {",
                "    console.log(JSON.stringify({event, hook, ...detail}));",
                "  } else {",
                "    const msg = detail && detail.msg ? detail.msg : '';",
                "    console.log(`${LOG_PREFIX}[${event}] ${hook} ${msg}`);",
                "  }",
                "}",
                "",
                # Helper: sigMatchesAt — compare bytes at addr to space-separated hex sig (?? = wildcard)
                "function sigMatchesAt(addr, sig) {",
                "  const tokens = sig.split(/\\s+/).filter(function (t) { return t.length > 0; });",
                "  if (tokens.length === 0) return false;",
                "  let bytes;",
                "  try {",
                "    bytes = new Uint8Array(addr.readByteArray(tokens.length));",
                "  } catch (e) {",
                "    return false;",
                "  }",
                "  for (let i = 0; i < tokens.length; i++) {",
                "    if (tokens[i] === '??') continue;",
                "    if (bytes[i] !== parseInt(tokens[i], 16)) return false;",
                "  }",
                "  return true;",
                "}",
                "",
                *scenario_block,
                *blocks,
                "",
                "(function main() {",
                *main_calls,
                "})();",
            ]
        )

    def save_script(self, path: Path, specs: Iterable[HookSpec]) -> None:
        script = self.generate_script(specs)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(script, encoding="utf-8")

    def load_hookspecs(self, path: Path) -> list[HookSpec]:
        return HookSpecStore.load(path)

    def _safe_name(self, spec: HookSpec) -> str:
        if spec.name:
            return "".join(ch if ch.isalnum() else "_" for ch in spec.name)
        return f"offset_{hex(spec.offset)[2:]}"

    def _render_hook_block(self, spec: HookSpec) -> str:
        import json as _json  # local import to avoid touching module-level imports on this branch

        name = self._safe_name(spec)
        name_lit = _js_str(name)
        module_lit = _js_str(spec.module)
        offset_hex = hex(spec.offset)
        log_args = spec.hook.onEnter.log_args or []
        hexdump_args = spec.hook.onEnter.hexdump_args or []
        log_ret = spec.hook.onLeave.log_ret
        hexdump_ret = spec.hook.onLeave.hexdump_ret
        string_args = self.string_args
        string_ret = self.string_ret

        # Build [primary, *aliases] candidate list. JSON-encoded to safely embed
        # arbitrary names (handles quotes / backslashes / unicode in module names).
        candidates = [spec.module, *spec.module_aliases]
        candidates_js = _json.dumps(candidates)

        lines = [
            f"function hook_{name}() {{",
            f"  const moduleCandidates = {candidates_js};",
            "  let mod = null;",
            "  let moduleName = null;",
            "  for (const candidate of moduleCandidates) {",
            "    try { mod = Process.getModuleByName(candidate); } catch (e) {}",
            "    if (mod) { moduleName = candidate; break; }",
            "  }",
            "  if (!mod) {",
            '    logEvent("error", moduleCandidates[0], {msg: "module not loaded; tried " + moduleCandidates.join(", ")});',
            "    return;",
            "  }",
            "  const base = mod.base;",
            f"  let target = base.add({offset_hex});",
        ]

        if spec.sig:
            sig_lit = _js_str(spec.sig)
            lines.extend(
                [
                    f"  const sig = {sig_lit};",
                    # Trigger fallback when bytes at base+offset don't match expected sig
                    "  if (!sigMatchesAt(target, sig)) {",
                    "    const scanLen = SCAN_SIZE > 0 ? SCAN_SIZE : mod.size;",
                    "    try {",
                    "      const matches = Memory.scanSync(base, scanLen, sig);",
                    "      if (matches && matches.length > 0) {",
                    "        target = matches[0].address;",
                    f"        logEvent(\"sigmatch\", moduleName, {{hook: {name_lit}, addr: ptrToHex(target)}});",
                    "      } else {",
                    f"        logEvent(\"error\", moduleName, {{hook: {name_lit}, msg: \"signature not found in module\"}});",
                    "      }",
                    "    } catch (e) {",
                    f"      logEvent(\"error\", moduleName, {{hook: {name_lit}, msg: \"signature scan error: \" + e}});",
                    "    }",
                    "  }",
                ]
            )

        # ----- onEnter body -----
        on_enter_lines: list[str] = [
            # Counter increments ONCE per call (was bugged: incremented per arg)
            f"            hookStats[{name_lit}] = (hookStats[{name_lit}] || 0) + 1;",
            f"            const _count = hookStats[{name_lit}];",
        ]
        for index in log_args:
            on_enter_lines.append(
                f'            logEvent("enter", {name_lit}, '
                f"{{arg: {index}, value: ptrToHex(args[{index}]), count: _count}});"
            )
        for index in hexdump_args:
            on_enter_lines.extend(
                [
                    "            try {",
                    f'              logEvent("hexdump", {name_lit}, '
                    f"{{arg: {index}, msg: hexdump(args[{index}], {{length: HEXDUMP_LEN}})}});",
                    "            } catch (e) {",
                    f'              logEvent("error", {name_lit}, '
                    f'{{msg: "hexdump failed for arg{index}: " + e}});',
                    "            }",
                ]
            )
        for index in string_args:
            on_enter_lines.extend(
                [
                    "            try {",
                    f"              const s = Memory.readCString(args[{index}], STRING_LEN);",
                    f'              logEvent("string", {name_lit}, {{arg: {index}, msg: s}});',
                    "            } catch (e) {",
                    f'              logEvent("error", {name_lit}, '
                    f'{{msg: "string read failed for arg{index}: " + e}});',
                    "            }",
                ]
            )

        # ----- onLeave body -----
        on_leave_lines: list[str] = []
        if log_ret:
            on_leave_lines.append(
                f'            logEvent("leave", {name_lit}, {{ret: ptrToHex(retval)}});'
            )
        if hexdump_ret:
            on_leave_lines.extend(
                [
                    "            try {",
                    f'              logEvent("hexdump", {name_lit}, '
                    f"{{msg: hexdump(retval, {{length: HEXDUMP_LEN}})}});",
                    "            } catch (e) {",
                    f'              logEvent("error", {name_lit}, '
                    f'{{msg: "hexdump failed for retval: " + e}});',
                    "            }",
                ]
            )
        if string_ret:
            on_leave_lines.extend(
                [
                    "            try {",
                    "              const s = Memory.readCString(retval, STRING_LEN);",
                    f'              logEvent("string", {name_lit}, {{msg: s}});',
                    "            } catch (e) {",
                    f'              logEvent("error", {name_lit}, '
                    f'{{msg: "string read failed for retval: " + e}});',
                    "            }",
                ]
            )

        lines.extend(
            [
                "  try {",
                "    let attempt = 1;",
                "    while (attempt <= RETRY_ATTACH) {",
                "      try {",
                "        Interceptor.attach(target, {",
                "          onEnter(args) {",
                *on_enter_lines,
                "          },",
                "          onLeave(retval) {",
                *on_leave_lines,
                "          },",
                "        });",
                f'        logEvent("hooked", {name_lit}, {{addr: ptrToHex(target)}});',
                "        break;",
                "      } catch (e) {",
                f'        logEvent("error", {name_lit}, '
                '{msg: "failed to hook attempt " + attempt + ": " + e});',
                "        if (attempt === RETRY_ATTACH) {",
                "          throw e;",
                "        }",
                "        attempt++;",
                "      }",
                "    }",
                "  } catch (e) {",
                f'    logEvent("error", {name_lit}, '
                '{msg: "failed to hook: " + e});',
                "  }",
                "}",
            ]
        )

        return "\n".join(lines)
