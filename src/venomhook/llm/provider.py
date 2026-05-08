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
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


__all__ = [
    "AnthropicProvider",
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


# ---------- Anthropic ----------


_DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


class AnthropicProvider(LLMProvider):
    """Anthropic Claude backend.

    The ``anthropic`` SDK is imported lazily inside :meth:`is_available`
    and :meth:`complete` so users without the optional ``[llm]`` extra
    can still ``from venomhook.llm import ...`` without raising.

    Authentication: API key is read from the ``ANTHROPIC_API_KEY``
    environment variable, or passed explicitly via the ``api_key``
    constructor argument. :meth:`is_available` returns False when the
    key is absent so callers can surface a helpful error in the CLI
    layer instead of leaking SDK exceptions.

    Default model is ``claude-haiku-4-5-20251001`` (fast and cheap, well
    suited to the structured outputs Phase 5 integration points need).
    Override via ``model=...`` or the CLI ``--llm-model`` flag.
    """

    name = "anthropic"

    def __init__(
        self,
        *,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        self.model = model or _DEFAULT_ANTHROPIC_MODEL
        self._api_key = api_key

    def _resolve_api_key(self) -> Optional[str]:
        return self._api_key or os.environ.get("ANTHROPIC_API_KEY")

    def is_available(self) -> bool:
        try:
            import anthropic  # type: ignore  # noqa: F401
        except ImportError:
            return False
        return bool(self._resolve_api_key())

    def complete(self, req: LLMRequest) -> LLMResponse:
        try:
            import anthropic  # type: ignore
        except ImportError as e:
            raise LLMError(
                "anthropic SDK not installed; install with "
                "`pip install -e '.[llm]'` or `pip install anthropic`."
            ) from e

        api_key = self._resolve_api_key()
        if not api_key:
            raise LLMError(
                "ANTHROPIC_API_KEY not set; export it in the environment "
                "or pass api_key to AnthropicProvider(...)."
            )

        try:
            client = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model=self.model,
                max_tokens=max(1, req.max_tokens),
                temperature=req.temperature,
                system=req.system or "",
                messages=[{"role": "user", "content": req.user}],
            )
        except Exception as e:  # SDK exceptions vary; collapse to LLMError
            raise LLMError(f"anthropic API call failed: {e}") from e

        text = _extract_text(message)
        usage = getattr(message, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        actual_model = str(getattr(message, "model", self.model))

        return LLMResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider=self.name,
            model=actual_model,
        )


def _extract_text(message: Any) -> str:
    """Concatenate every text block in a Claude Messages response.

    The SDK returns ``message.content`` as a list of typed blocks
    (``TextBlock``, ``ToolUseBlock``, etc.). Phase 5 integration points
    only ask for plain text completions, so we filter to text blocks
    and join. Robust to future block types (anything without ``.text``
    is silently skipped).
    """
    parts: list[str] = []
    for block in getattr(message, "content", []) or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)


# ---------- factory ----------


# Provider names known to the factory. Imports of optional SDKs happen inside
# each provider's methods so this list is cheap to read.
_PROVIDER_NAMES = ("echo", "anthropic", "openai", "local")


def list_providers() -> tuple[str, ...]:
    """Names accepted by :func:`get_provider`. Order is not significant."""
    return _PROVIDER_NAMES


def get_provider(name: str, *, model: Optional[str] = None) -> LLMProvider:
    """Construct a provider by name.

    Recognized names:
        - ``"echo"`` — :class:`EchoProvider`. Always available.
        - ``"anthropic"`` — :class:`AnthropicProvider`. Requires the
          ``anthropic`` SDK and ``ANTHROPIC_API_KEY``; both are checked
          lazily so import-time succeeds either way.
        - ``"openai"`` / ``"local"`` — placeholders, raise :class:`LLMError`.

    Pass ``model`` to override the backend's default model. Unknown names
    raise :class:`LLMError`.
    """
    n = name.lower().strip()
    if n == "echo":
        return EchoProvider(model=model) if model else EchoProvider()
    if n == "anthropic":
        return AnthropicProvider(model=model)
    if n in {"openai", "local"}:
        raise LLMError(
            f"provider {n!r} is not implemented yet — use 'echo' or 'anthropic'."
        )
    raise LLMError(
        f"unknown provider {name!r}; valid names: {list_providers()}"
    )
