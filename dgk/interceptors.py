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


class ForbiddenWordRule:
    """Enforces boundaries to catch data leak attempts and forbidden substrings."""

    name = "perimeter_compliance_filter"

    def enforce(self, context: RequestContext) -> CheckResult:
        if "forbidden" in context.request_text.lower():
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
        if payload.latency > 500:
            detected_faults["latency_fault"] = payload.latency
        if payload.abort_rate > 0.25:
            detected_faults["abort_fault"] = payload.abort_rate
        if payload.reentry_rate > 2.0:
            detected_faults["reentry_fault"] = payload.reentry_rate
        return len(detected_faults) == 0, detected_faults
