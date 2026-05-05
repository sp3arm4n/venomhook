from __future__ import annotations

from typing import Iterable, Optional

from venomhook.models import EndpointMeta, FunctionMeta, HookConfig, HookProto, HookSpec, OnEnterHook, OnLeaveHook


def _build_signature(fn: Optional[FunctionMeta], max_bytes: int = 12) -> Optional[str]:
    if not fn or not fn.raw_bytes:
        return None
    tokens = fn.raw_bytes.strip().split()
    if not tokens:
        return None
    return " ".join(tokens[:max_bytes])


def build_hookspecs(
    endpoints: Iterable[EndpointMeta],
    functions: list[FunctionMeta] | None = None,
    sig_max_bytes: int = 12,
) -> list[HookSpec]:
    fn_by_rva = {fn.rva: fn for fn in functions or [] if fn.rva is not None}
    seen_safe_names: set[str] = set()

    def _make_name(ep: EndpointMeta, fn: FunctionMeta | None) -> str:
        """Prefer reason, then function name, and uniquify in sanitized form."""

        def _to_safe(value: str) -> str:
            return "".join(ch if ch.isalnum() else "_" for ch in value)

        base = ep.reason[0] if ep.reason else (fn.name if fn and fn.name else f"endpoint_{hex(ep.rva)}")
        safe = _to_safe(base)
        if safe in seen_safe_names:
            base = f"{base}_{hex(ep.rva)}"
            safe = _to_safe(base)
        seen_safe_names.add(safe)
        return base
    hooks: list[HookSpec] = []
    for ep in endpoints:
        fn = fn_by_rva.get(ep.rva)
        sig = _build_signature(fn, max_bytes=sig_max_bytes)
        hook_cfg = HookConfig(
            onEnter=OnEnterHook(log_args=[0, 1], hexdump_args=[0], log_stack=False),
            onLeave=OnLeaveHook(log_ret=True, hexdump_ret=False),
        )
        proto = HookProto(ret=None, args=[])
        name = _make_name(ep, fn)
        hooks.append(
            HookSpec(
                module=ep.module,
                arch=ep.arch,
                offset=ep.rva,
                sig=sig,
                name=name,
                tags=ep.tags,
                proto=proto,
                hook=hook_cfg,
            )
        )
    return hooks
