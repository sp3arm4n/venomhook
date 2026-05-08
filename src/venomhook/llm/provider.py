"""LLM provider abstraction shared by all Phase 5 integration points.

Five integration points (semantic tagging, proto inference, Java↔Native
flow description, runtime report summary, signature self-recovery) each
build different prompts but share one provider interface. Adding a new
backend means subclassing :class:`LLMProvider` and registering it in
:func:`get_provider` — no other module needs to change.

Design notes:
    - Importing the module never imports SDKs. Real backends (anthropic,
      openai, ...) lazy-import their SDK inside :meth:`is_available` and
      :meth:`complete`. A user without the SDK installed gets a clean
      ``LLMError`` at *call* time, not at *import* time.
    - :class:`EchoProvider` is a deterministic test double that returns
      a canned echo of the request. Tests for the integration points can
      target ``echo`` and stay hermetic.
    - :meth:`LLMRequest.cache_key` deliberately omits the provider name —
      the cache layer (:mod:`venomhook.llm.cache`) layers (provider, model)
      on top so that swapping providers invalidates the cache.

The token-counting fields on :class:`LLMResponse` are advisory; providers
that cannot report them set them to 0. The budget tracker
(:mod:`venomhook.llm.budget`) treats 0 as "unknown" and falls back to a
rough char/4 estimate.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


__all__ = [
    "EchoProvider",
    "LLMError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "get_provider",
    "list_providers",
]


class LLMError(RuntimeError):
    """Raised for any LLM failure: missing SDK, bad credentials, API error, malformed response."""


@dataclass(frozen=True)
class LLMRequest:
    """A single LLM call. Provider-agnostic; backends translate to their wire format."""

    system: str
    user: str
    max_tokens: int = 1024
    temperature: float = 0.0
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def cache_key(self) -> str:
        """Stable hash over the *content* of the request.

        The cache layer prepends (provider, model) so two providers can
        coexist for the same logical request without colliding.
        """
        payload = {
            "system": self.system,
            "user": self.user,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "metadata": list(self.metadata),
        }
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class LLMResponse:
    """The decoded result of an LLM call."""

    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str = ""
    model: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "provider": self.provider,
            "model": self.model,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LLMResponse":
        return cls(
            text=data["text"],
            input_tokens=int(data.get("input_tokens", 0)),
            output_tokens=int(data.get("output_tokens", 0)),
            provider=data.get("provider", ""),
            model=data.get("model", ""),
        )


class LLMProvider(ABC):
    """Common contract every backend implements."""

    name: str = "abstract"
    model: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True iff the backend can satisfy a call right now.

        Implementations should check for SDK availability *and* credentials
        but must not perform a network round-trip.
        """

    @abstractmethod
    def complete(self, req: LLMRequest) -> LLMResponse:
        """Synchronous single-turn completion. Raises :class:`LLMError` on failure."""


class EchoProvider(LLMProvider):
    """Deterministic test double — never makes a network call.

    Returns ``f"[echo:{name}] {req.user}"`` (truncated to ``max_tokens * 4``
    chars to mimic an output cap). Used by tests for integration points so
    the suite never depends on a live API. ``model`` defaults to ``"echo-1"``.
    """

    name = "echo"

    def __init__(self, model: str = "echo-1") -> None:
        self.model = model

    def is_available(self) -> bool:
        return True

    def complete(self, req: LLMRequest) -> LLMResponse:
        body = f"[echo:{self.name}] {req.user}"
        cap = max(1, req.max_tokens * 4)
        text = body[:cap]
        return LLMResponse(
            text=text,
            input_tokens=_rough_token_count(req.system) + _rough_token_count(req.user),
            output_tokens=_rough_token_count(text),
            provider=self.name,
            model=self.model,
        )


def _rough_token_count(text: str) -> int:
    """char/4 heuristic; good enough for budget accounting when the SDK doesn't report usage."""
    return max(1, len(text) // 4)


# Provider names known to the factory. Imports of optional SDKs happen inside
# the constructor of each provider class so this list is cheap to read.
_PROVIDER_NAMES = ("echo", "anthropic", "openai", "local")


def list_providers() -> tuple[str, ...]:
    """Names accepted by :func:`get_provider`. Order is not significant."""
    return _PROVIDER_NAMES


def get_provider(name: str, *, model: Optional[str] = None) -> LLMProvider:
    """Construct a provider by name.

    Recognized names:
        - ``"echo"`` — :class:`EchoProvider`. Always available.
        - ``"anthropic"`` — Anthropic Claude via the ``anthropic`` SDK.
          Wired in Phase 5 Unit 4; until then this name raises
          :class:`LLMError` advising to use ``"echo"`` or wait for Unit 4.
        - ``"openai"`` / ``"local"`` — placeholders, raise :class:`LLMError`.

    Pass ``model`` to override the backend's default model. Unknown names
    raise :class:`LLMError`.
    """
    n = name.lower().strip()
    if n == "echo":
        return EchoProvider(model=model) if model else EchoProvider()
    if n in {"anthropic", "openai", "local"}:
        raise LLMError(
            f"provider {n!r} is not implemented yet — only {'echo'!r} is available "
            f"in this build. See pyproject.toml `[llm]` extras (Phase 5 Unit 4)."
        )
    raise LLMError(
        f"unknown provider {name!r}; valid names: {list_providers()}"
    )
