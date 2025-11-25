from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Tuple

from venomhook.models import EndpointMeta, FunctionMeta, StaticMeta


NETWORK_IMPORTS = {"connect", "send", "recv", "socket", "WSAStartup", "InternetOpen", "HttpSendRequest", "WinHttpOpen"}
FILE_IMPORTS = {"CreateFile", "ReadFile", "WriteFile", "fopen", "open", "fread", "fwrite"}
CRYPTO_WORDS = {"encrypt", "decrypt", "aes", "rsa", "crypto"}
AUTH_WORDS = {"auth", "token", "login", "session", "password", "cookie"}
URL_WORDS = {"http", "https"}


@dataclass
class ScoreConfig:
    network_weight: int = 30
    file_weight: int = 20
    auth_weight: int = 15  # multiplied by distinct auth keywords count
    url_weight: int = 10
    crypto_weight: int = 10
    callers_per: int = 2
    callers_cap: int = 10
    callees_per: int = 1
    callees_cap: int = 5
    basic_blocks_bonus: int = 5
    basic_blocks_threshold: int = 10


def _score_function(fn: FunctionMeta, cfg: ScoreConfig) -> Tuple[int, list[str], list[str]]:
    score = 0
    tags: list[str] = []
    reasons: list[str] = []

    imports_lower = {imp.lower() for imp in fn.imports}
    strings_lower = [s.lower() for s in fn.strings]

    if imports_lower & {i.lower() for i in NETWORK_IMPORTS}:
        tags.append("network")
        reasons.append(f"imports: {', '.join(sorted(imports_lower & {i.lower() for i in NETWORK_IMPORTS}))}")
        score += cfg.network_weight

    if imports_lower & {i.lower() for i in FILE_IMPORTS}:
        tags.append("file")
        reasons.append(f"imports: {', '.join(sorted(imports_lower & {i.lower() for i in FILE_IMPORTS}))}")
        score += cfg.file_weight

    if any(word in s for s in strings_lower for word in AUTH_WORDS):
        tags.append("auth")
        counts = Counter(word for s in strings_lower for word in AUTH_WORDS if word in s)
        reasons.append("strings: " + ", ".join(f"{k}({v})" for k, v in counts.items()))
        score += cfg.auth_weight * len(counts)

    if any(word in s for s in strings_lower for word in URL_WORDS):
        tags.append("network")
        score += cfg.url_weight
        reasons.append("strings: url/http")

    if any(word in s for s in strings_lower for word in CRYPTO_WORDS):
        tags.append("crypto")
        score += cfg.crypto_weight
        reasons.append("strings: crypto keyword")

    if fn.callers:
        score += min(len(fn.callers) * cfg.callers_per, cfg.callers_cap)
        reasons.append(f"callers: {len(fn.callers)}")

    if fn.callees:
        score += min(len(fn.callees) * cfg.callees_per, cfg.callees_cap)
        reasons.append(f"callees: {len(fn.callees)}")

    if fn.basic_blocks and fn.basic_blocks > cfg.basic_blocks_threshold:
        score += cfg.basic_blocks_bonus
        reasons.append(f"basic_blocks: {fn.basic_blocks}")

    return score, sorted(set(tags)), reasons


def score_endpoints(meta: StaticMeta, top_n: int = 10, config: ScoreConfig | None = None) -> list[EndpointMeta]:
    cfg = config or ScoreConfig()
    endpoints: list[EndpointMeta] = []
    for fn in meta.functions:
        if fn.rva is None:
            continue
        score, tags, reasons = _score_function(fn, cfg)
        if score == 0:
            continue
        endpoints.append(
            EndpointMeta(
                module=meta.binary.name,
                arch=meta.binary.arch or "unknown",
                rva=fn.rva,
                score=score,
                tags=tags,
                reason=reasons,
            )
        )
    endpoints.sort(key=lambda item: item.score, reverse=True)
    return endpoints[:top_n]
