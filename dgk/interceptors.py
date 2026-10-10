"""
Perimeter checks.

An interceptor is a single named rule that inspects a request before the
kernel commits anything, and either passes it or rejects it with a reason.
The registry runs them in registration order and stops at the first failure,
so a rejection always names exactly one rule.

`Rule`, `RuleRegistry` and `RequestBuilder` did not survive in
the recovered source -- they were referenced by the kernel but their
definitions were lost. They are reconstructed here from their call sites,
which pin the contracts exactly: see RECONSTRUCTION.md.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Protocol, Tuple, runtime_checkable

from .taxonomy import RequestContext, CheckResult, TelemetryReading

__all__ = [
    "Rule",
    "RuleRegistry",
    "RequestBuilder",
    "ForbiddenWordRule",
    "HealthLimitCheck",
]


@runtime_checkable
class Rule(Protocol):
    """A named perimeter rule."""

    name: str

    def enforce(self, context: RequestContext) -> CheckResult:
        """Pass the request, or reject it with a reason."""
        ...


class RuleRegistry:
    """Runs registered interceptors in order, failing closed at the first
    rejection so a rejected request names one rule rather than a list."""

    def __init__(self) -> None:
        self._interceptors: List[Rule] = []

    def register(self, interceptor: Rule) -> None:
        self._interceptors.append(interceptor)

    @property
    def registered(self) -> Tuple[str, ...]:
        return tuple(i.name for i in self._interceptors)

    def evaluate(self, context: RequestContext) -> CheckResult:
        for interceptor in self._interceptors:
            result = interceptor.enforce(context)
            if not result.passed:
                return result
        return CheckResult(True, "interceptor_registry", "all interceptors passed")


class RequestBuilder:
    """Turns a raw request payload into the RequestContext the rules read.

    Accepts either a flat `text` field or a `messages` list, so a chat-shaped
    payload and a plain one reach the interceptors identically. When both are
    present `text` wins, matching how the kernel builds its payload.
    """

    @staticmethod
    def normalize(payload: Dict[str, Any]) -> RequestContext:
        messages = list(payload.get("messages") or [])
        text = payload.get("text")
        if not text:
            text = "\n".join(
                str(m.get("content", "")) for m in messages if isinstance(m, dict)
            )
        return RequestContext(
            request_text=str(text or ""),
            raw_request=dict(payload),
            messages=messages,
            metadata=dict(payload.get("metadata") or {}),
            audit_enabled=bool(payload.get("audit_enabled", True)),
        )


# Characters that render as nothing, and Cyrillic or Greek letters that render
# like a Latin one. Folded away before matching so they cannot hide a word.
_INVISIBLE = {ord(c): None for c in "\u00ad\u034f\u180e\u200b\u200c\u200d\u2060\ufeff"}
_LOOKALIKES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u0458": "j",
    "\u0501": "d", "\u04bb": "h", "\u0432": "b", "\u043d": "h", "\u043a": "k",
    "\u043c": "m", "\u0442": "t", "\u03bf": "o", "\u03b1": "a", "\u03b5": "e",
    "\u03b9": "i", "\u03bd": "v", "\u03c1": "p", "\u03ba": "k", "\u03b2": "b",
}


def fold_for_matching(text: str) -> str:
    """Lowercase text with invisible characters removed and lookalike letters
    replaced by the Latin letter they imitate."""
    folded = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).lower()
    return "".join(_LOOKALIKES.get(ch, ch) for ch in folded)


class ForbiddenWordRule:
    """Enforces boundaries to catch data leak attempts and forbidden substrings.

    The word is matched after folding invisible characters and lookalike
    letters, and again with every non-letter removed, so "f\u043erbidden" and
    "for-bidden" are caught. The second pass can also match across a word
    boundary ("for bidden"). That is accepted: this is a record-quality
    screen, not a defence against a determined evader, and a synonym or a
    different spelling still passes.
    """

    name = "perimeter_compliance_filter"
    _SQUASH = re.compile(r"[\W_]+")

    def enforce(self, context: RequestContext) -> CheckResult:
        folded = fold_for_matching(context.request_text)
        if "forbidden" in folded or "forbidden" in self._SQUASH.sub("", folded):
            return CheckResult(
                False,
                self.name,
                "Security Exception: Forbidden injection sequence detected.",
            )
        return CheckResult(True, self.name)


class HealthLimitCheck:
    """Validates structural operation criteria directly out-of-band."""

    def verify_bounds(self, payload: TelemetryReading) -> Tuple[bool, Dict[str, float]]:
        detected_faults: Dict[str, float] = {}
        # "not x <= limit" also fails closed for NaN, which compares False both ways.
        if not payload.latency <= 500:
            detected_faults["latency_fault"] = payload.latency
        if not payload.abort_rate <= 0.25:
            detected_faults["abort_fault"] = payload.abort_rate
        if not payload.reentry_rate <= 2.0:
            detected_faults["reentry_fault"] = payload.reentry_rate
        return len(detected_faults) == 0, detected_faults
