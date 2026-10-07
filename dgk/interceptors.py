"""
Perimeter checks.

An interceptor is a single named rule that inspects a request before the
kernel commits anything, and either passes it or rejects it with a reason.
The registry runs them in registration order and stops at the first failure,
so a rejection always names exactly one rule.

`Interceptor`, `InterceptorRegistry` and `RequestNormalizer` did not survive in
the recovered source -- they were referenced by the kernel but their
definitions were lost. They are reconstructed here from their call sites,
which pin the contracts exactly: see RECONSTRUCTION.md.
"""

from __future__ import annotations

from typing import Any, Dict, List, Protocol, Tuple, runtime_checkable

from .taxonomy import GovernanceContext, RuleResult, TelemetryMetricsPayload

__all__ = [
    "Interceptor",
    "InterceptorRegistry",
    "RequestNormalizer",
    "ContentFilterInterceptor",
    "RuntimeBoundaryBarrier",
]


@runtime_checkable
class Interceptor(Protocol):
    """A named perimeter rule."""

    name: str

    def enforce(self, context: GovernanceContext) -> RuleResult:
        """Pass the request, or reject it with a reason."""
        ...


class InterceptorRegistry:
    """Runs registered interceptors in order, failing closed at the first
    rejection so a rejected request names one rule rather than a list."""

    def __init__(self) -> None:
        self._interceptors: List[Interceptor] = []

    def register(self, interceptor: Interceptor) -> None:
        self._interceptors.append(interceptor)

    @property
    def registered(self) -> Tuple[str, ...]:
        return tuple(i.name for i in self._interceptors)

    def evaluate(self, context: GovernanceContext) -> RuleResult:
        for interceptor in self._interceptors:
            result = interceptor.enforce(context)
            if not result.passed:
                return result
        return RuleResult(True, "interceptor_registry", "all interceptors passed")


class RequestNormalizer:
    """Turns a raw request payload into the GovernanceContext the rules read.

    Accepts either a flat `text` field or a `messages` list, so a chat-shaped
    payload and a plain one reach the interceptors identically. When both are
    present `text` wins, matching how the kernel builds its payload.
    """

    @staticmethod
    def normalize(payload: Dict[str, Any]) -> GovernanceContext:
        messages = list(payload.get("messages") or [])
        text = payload.get("text")
        if not text:
            text = "\n".join(
                str(m.get("content", "")) for m in messages if isinstance(m, dict)
            )
        return GovernanceContext(
            request_text=str(text or ""),
            raw_request=dict(payload),
            messages=messages,
            metadata=dict(payload.get("metadata") or {}),
            audit_enabled=bool(payload.get("audit_enabled", True)),
        )


class ContentFilterInterceptor:
    """Enforces boundaries to catch data leak attempts and forbidden substrings."""

    name = "perimeter_compliance_filter"

    def enforce(self, context: GovernanceContext) -> RuleResult:
        if "forbidden" in context.request_text.lower():
            return RuleResult(
                False,
                self.name,
                "Security Exception: Forbidden injection sequence detected.",
            )
        return RuleResult(True, self.name)


class RuntimeBoundaryBarrier:
    """Validates structural operation criteria directly out-of-band."""

    def verify_bounds(
        self, payload: TelemetryMetricsPayload
    ) -> Tuple[bool, Dict[str, float]]:
        detected_faults: Dict[str, float] = {}
        if payload.latency > 500:
            detected_faults["latency_fault"] = payload.latency
        if payload.abort_rate > 0.25:
            detected_faults["abort_fault"] = payload.abort_rate
        if payload.reentry_rate > 2.0:
            detected_faults["reentry_fault"] = payload.reentry_rate
        return len(detected_faults) == 0, detected_faults
