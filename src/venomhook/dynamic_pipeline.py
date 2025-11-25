from __future__ import annotations

from pathlib import Path
from typing import Iterable

from venomhook.models import HookSpec
from venomhook.store import HookSpecStore


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
        scenario_block = []
        if self.scenario_message:
            scenario_block = [
                "",
                f'function runScenario() {{ send({{type: "scenario", message: "{self.scenario_message}"}}); }}',
            ]
        main_calls = ["  " + call for call in calls]
        if self.scenario_message and self.auto_start_scenario:
            main_calls.append("  runScenario();")
        return "\n".join(
            [
                "// Auto-generated Frida script",
                f"// target: {self.target}",
                "",
                f'const LOG_FORMAT = "{self.log_format}";',
                f'const LOG_PREFIX = "{self.log_prefix}";',
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
        name = self._safe_name(spec)
        offset_hex = hex(spec.offset)
        log_args = spec.hook.onEnter.log_args or []
        hexdump_args = spec.hook.onEnter.hexdump_args or []
        log_ret = spec.hook.onLeave.log_ret
        hexdump_ret = spec.hook.onLeave.hexdump_ret
        string_args = self.string_args
        string_ret = self.string_ret

        lines = [
            f"function hook_{name}() {{",
            f'  const moduleName = "{spec.module}";',
            "  const base = Module.findBaseAddress(moduleName);",
            "  if (!base) {",
            '    logEvent("error", moduleName, {msg: "module not loaded"});',
            "    return;",
            "  }",
            f"  let target = base.add({offset_hex});",
        ]

        if spec.sig:
            lines.extend(
                [
                    f'  const sig = "{spec.sig}";',
                    "  if (!target.readByteArray(1)) {",
                    "    const scanLen = SCAN_SIZE > 0 ? SCAN_SIZE : Module.getBaseSize(moduleName);",
                    "    Memory.scan(base, scanLen, sig, {",
                    "      onMatch(addr) {",
                    "        target = addr;",
                    '        logEvent("sigmatch", moduleName, {addr: ptrToHex(target)});',
                    "      },",
                    "      onError(reason) {",
                    '        logEvent("error", moduleName, {msg: `signature scan error: ${reason}`});',
                    "      },",
                    "      onComplete() {},",
                    "    });",
                    "  }",
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
            ]
        )

        for index in log_args:
            lines.extend(
                [
                    f'        hookStats["{name}"] = (hookStats["{name}"] || 0) + 1;',
                    f'        logEvent("enter", "{name}", {{arg: {index}, value: ptrToHex(args[{index}]), count: hookStats["{name}"]}});',
                ]
            )
        for index in hexdump_args:
            lines.extend(
                [
                    f"        try {{",
                    f'          logEvent("hexdump", "{name}", {{arg: {index}, msg: hexdump(args[{index}], {{length: HEXDUMP_LEN}})}});',
                    "        } catch (e) {",
                    f'          logEvent("error", "{name}", {{msg: "hexdump failed for arg{index}: " + e}});',
                    f"        }}",
                ]
            )
        for index in string_args:
            lines.extend(
                [
                    "        try {",
                    f'          const s = Memory.readCString(args[{index}], STRING_LEN);',
                    f'          logEvent("string", "{name}", {{arg: {index}, msg: s}});',
                    "        } catch (e) {",
                    f'          logEvent("error", "{name}", {{msg: "string read failed for arg{index}: " + e}});',
                    "        }",
                ]
            )

        lines.extend(
            [
                "      },",
                "      onLeave(retval) {",
            ]
        )

        if log_ret:
            lines.append(f'        logEvent("leave", "{name}", {{ret: ptrToHex(retval)}});')
        if hexdump_ret:
            lines.extend(
                [
                    "        try {",
                    f'          logEvent("hexdump", "{name}", {{msg: hexdump(retval, {{length: HEXDUMP_LEN}})}});',
                    "        } catch (e) {",
                    '          logEvent("error", "{name}", {msg: "hexdump failed for retval: " + e});',
                    "        }",
                ]
            )
        if string_ret:
            lines.extend(
                [
                    "        try {",
                    f'          const s = Memory.readCString(retval, STRING_LEN);',
                    f'          logEvent("string", "{name}", {{msg: s}});',
                    "        } catch (e) {",
                    f'          logEvent("error", "{name}", {{msg: "string read failed for retval: " + e}});',
                    "        }",
                ]
            )

        lines.extend(
            [
                "          },",
                "        });",
                f'        logEvent("hooked", "{name}", {{addr: ptrToHex(target)}});',
                "        break;",
                "      } catch (e) {",
                f'        logEvent("error", "{name}", {{msg: "failed to hook attempt " + attempt + ": " + e}});',
                "        if (attempt === RETRY_ATTACH) {",
                "          throw e;",
                "        }",
                "        attempt++;",
                "      }",
                "    }",
                "  } catch (e) {",
                f'    logEvent("error", "{name}", {{msg: "failed to hook: " + e}});',
                "  }",
                "}",
            ]
        )

        return "\n".join(lines)
