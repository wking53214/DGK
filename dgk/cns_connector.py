"""Optional connector to CNS (``cns.gate``).

DGK is independent. It has no runtime dependency, imports nothing from CNS when
it loads, and its whole suite passes with CNS absent. This module is the one
place that knows CNS exists, and it asks for CNS only when one of its
functions is called. Without CNS installed those calls raise
:class:`CnsNotInstalled` with the install command; nothing else in DGK is
affected.

What connecting means
---------------------
CNS's shared gate contract is ``cns.gate.GateResult`` (``gate``, ``position``,
``outcome``, ``reason``, ``subject``, ``subject_digest``). DGK's kernel checks a
transaction in several steps and writes what it did to a signed trail. Two of
those steps are pure checks that read a request and change nothing, and this
module offers them as CNS gates so a consumer that speaks CNS can resolve them
alongside gates from other repositories:

* :class:`PerimeterGate` runs DGK's perimeter rules (by default the forbidden
  sequence screen) over the request text.
* :class:`HealthGate` runs DGK's health limits over the five telemetry values.

Both are ``ALPHA`` gates: they judge a request before anything is committed.
Neither touches the kernel, its regime tracker, its ledger or its audit trail.
That is a real difference from a transaction: the kernel moves its regime on
every telemetry reading it classifies, refused or not, and these gates do not.
Asking a gate is not submitting a transaction.

The mapping, and why
--------------------
=============================  =========================================
DGK                            CNS
=============================  =========================================
perimeter rule passes          ``PASS``
perimeter rule rejects         ``TERMINAL_BREACH``  (a forbidden sequence
                               in the text does not become allowed by
                               asking again)
health limits hold             ``PASS``
health limit breached          ``RETRY``  (load and latency are the
                               system's present condition; the request
                               may be fine when it eases)
telemetry that is not a        ``TERMINAL_BREACH``, unbound  (nothing was
finite non-negative number     read, so nothing is bound)
a rule that raises             ``TERMINAL_BREACH``  (a check that cannot
                               answer is never read as a pass)
=============================  =========================================

``subject_digest`` is ``cns.gate.subject_digest`` over what the check read: the
request text for the perimeter (``{"text": ...}``), or, for a request mapping,
the whole mapping (``{"request": {...}}``), and the five telemetry readings for
health (``{"telemetry": {...}}``). A verdict bound to one request does not bind
to another.

A request mapping is screened over every string it carries, in every field and
at any depth (``text``, ``messages``, ``metadata`` and any other key), not only
the ``text`` the kernel builds its payload from. A field the gate cannot read
(bytes, an object, a non-text key, a request that contains itself) is an
unbound ``TERMINAL_BREACH``. A ``PerimeterGate`` with an empty rule registry is
refused at construction with ``ValueError``: no rules would pass everything.

DGK has only the input end. ``cns_chain(...).complete()`` is ``False`` by
design: the omega end comes from a repository that has one (DIT judges
generated text, URE judges a regime).

Install with the extra: ``pip install 'dgk[cns]'``.
"""

from __future__ import annotations

import dataclasses
import importlib
from collections.abc import Mapping
from types import ModuleType
from typing import Any, Optional

from .interceptors import ForbiddenWordRule, HealthLimitCheck, RequestBuilder, RuleRegistry
from .kernel import Kernel, TelemetryError

__all__ = [
    "CnsNotInstalled",
    "HealthGate",
    "PerimeterGate",
    "cns_available",
    "cns_chain",
    "request_digest",
    "telemetry_digest",
]

INSTALL_HINT = "pip install 'dgk[cns]'"

REQUEST_SUBJECT = "request"
TELEMETRY_SUBJECT = "telemetry"


class CnsNotInstalled(ImportError):
    """Raised by this module's functions when ``cns`` cannot be imported."""


def _cns_gate() -> ModuleType:
    """Import ``cns.gate`` on demand, or say exactly what is missing."""
    try:
        return importlib.import_module("cns.gate")
    except ImportError as exc:
        raise CnsNotInstalled(
            "dgk.cns_connector needs the CNS package (cns.gate), which is not "
            f"installed. Install it with: {INSTALL_HINT}. DGK itself works "
            "without it."
        ) from exc


def cns_available() -> bool:
    """Whether the CNS gate contract can be imported in this environment."""
    try:
        _cns_gate()
    except CnsNotInstalled:
        return False
    return True


class _Unreadable(Exception):
    """A request field the perimeter cannot read faithfully."""


def _strings(payload: Mapping[str, Any]) -> list:
    """Every string a request mapping carries, keys included, at any depth.

    Iterative, so depth cannot exhaust the stack. A container met twice on the
    current path (a cycle), or a value that is not text, a number, a bool,
    None, a mapping or a list, cannot be judged and raises ``_Unreadable``.
    """
    found: list = []
    stack: list = [(payload, ())]
    while stack:
        node, path = stack.pop()
        if isinstance(node, str):
            found.append(node)
        elif node is None or isinstance(node, (bool, int, float)):
            continue
        elif isinstance(node, (Mapping, list, tuple)):
            if id(node) in path:
                raise _Unreadable("the request refers to itself")
            inner = path + (id(node),)
            if isinstance(node, Mapping):
                children = []
                for key, value in node.items():
                    if not isinstance(key, str):
                        raise _Unreadable(f"a request key is a {type(key).__name__}, not text")
                    children.extend((key, value))
            else:
                children = list(node)
            stack.extend((child, inner) for child in reversed(children))
        else:
            raise _Unreadable(f"a request field holds a {type(node).__name__}, which is not text")
    return found


def _judged(candidate: object) -> tuple:
    """What the perimeter screens and what its verdict binds to.

    Plain text is screened and bound as ``{"text": ...}``, as before. A request
    mapping is screened over every string it carries in any field (``text``,
    ``messages``, ``metadata`` or any other key), and the verdict binds to the
    whole mapping (``{"request": ...}``), so a verdict on one request cannot be
    moved onto another that carries more.
    """
    if isinstance(candidate, str):
        return RequestBuilder.normalize({"text": candidate}).request_text, {"text": candidate}, None
    if isinstance(candidate, Mapping):
        payload = dict(candidate)
        return "\n".join(_strings(payload)), {"request": payload}, payload
    raise TypeError(
        f"the perimeter gate judges request text or a request mapping; got {type(candidate).__name__}"
    )


def request_digest(candidate: object) -> str:
    """The digest a bound perimeter verdict on ``candidate`` carries.

    Pass it, with ``REQUEST_SUBJECT``, to ``GateResult.binds`` to check that a
    verdict was issued against exactly this request.
    """
    return _cns_gate().subject_digest(_judged(candidate)[1])


def telemetry_digest(telemetry: Mapping[str, Any]) -> str:
    """The digest a bound health verdict on ``telemetry`` carries (the five readings it read)."""
    reading = Kernel._read_telemetry(dict(telemetry))
    return _cns_gate().subject_digest({"telemetry": dataclasses.asdict(reading)})


class PerimeterGate:
    """DGK's perimeter rules as a ``cns.gate.Gate`` at the ``ALPHA`` end."""

    name = "dgk.perimeter"

    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        _cns_gate()  # fail here, at construction, not on first use
        if registry is None:
            registry = RuleRegistry()
            registry.register(ForbiddenWordRule())
        if not tuple(getattr(registry, "registered", ())):
            raise ValueError(
                "the perimeter registry has no rules; an empty registry would pass everything"
            )
        self._registry = registry

    @property
    def position(self) -> Any:
        return _cns_gate().GatePosition.ALPHA

    def check(self, candidate: object) -> Any:
        gate = _cns_gate()
        try:
            text, content, payload = _judged(candidate)
            bound = {"subject": REQUEST_SUBJECT, "subject_digest": gate.subject_digest(content)}
        except (_Unreadable, TypeError, ValueError, RecursionError) as exc:
            if not isinstance(candidate, (str, Mapping)):
                raise
            return gate.GateResult(
                gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.TERMINAL_BREACH,
                reason=f"the request cannot be read in full ({exc}); nothing was judged")
        try:
            if not tuple(self._registry.registered):
                raise ValueError("the perimeter registry has no rules")
            context = RequestBuilder.normalize({"text": text} if payload is None else payload)
            context = dataclasses.replace(context, request_text=text)
            verdict = self._registry.evaluate(context)
        except Exception as exc:  # a rule that cannot answer is never read as a pass
            return gate.GateResult(
                gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.TERMINAL_BREACH,
                reason=f"a perimeter rule raised {type(exc).__name__} and could not answer; "
                       "a check that cannot answer is never read as a pass",
                **bound)
        if verdict.passed:
            return gate.GateResult(
                gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.PASS,
                reason=verdict.details or "all perimeter rules passed", **bound)
        return gate.GateResult(
            gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.TERMINAL_BREACH,
            reason=f"{verdict.rule_identifier}: {verdict.details}", **bound)


class HealthGate:
    """DGK's health limits as a ``cns.gate.Gate`` at the ``ALPHA`` end."""

    name = "dgk.health"

    def __init__(self, limits: Optional[HealthLimitCheck] = None) -> None:
        _cns_gate()
        self._limits = limits or HealthLimitCheck()

    @property
    def position(self) -> Any:
        return _cns_gate().GatePosition.ALPHA

    def check(self, candidate: object) -> Any:
        gate = _cns_gate()
        if not isinstance(candidate, Mapping):
            raise TypeError(f"the health gate judges a telemetry mapping; got {type(candidate).__name__}")
        try:
            reading = Kernel._read_telemetry(dict(candidate))
        except TelemetryError as exc:
            return gate.GateResult(
                gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.TERMINAL_BREACH,
                reason=f"telemetry cannot be read ({exc}); nothing was judged")
        bound = {"subject": TELEMETRY_SUBJECT,
                 "subject_digest": gate.subject_digest({"telemetry": dataclasses.asdict(reading)})}
        ok, faults = self._limits.verify_bounds(reading)
        if ok:
            return gate.GateResult(
                gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.PASS,
                reason="every health limit holds", **bound)
        shown = ", ".join(f"{name}={value:g}" for name, value in sorted(faults.items()))
        return gate.GateResult(
            gate=self.name, position=gate.GatePosition.ALPHA, outcome=gate.GateOutcome.RETRY,
            reason=f"a health limit is breached ({shown}); ask again when the system has eased", **bound)


def cns_chain(registry: Optional[RuleRegistry] = None, limits: Optional[HealthLimitCheck] = None) -> Any:
    """A ``cns.gate.GateChain`` holding DGK's two gates in the ``alpha`` slot.

    ``omega`` stays empty: DGK has no outcome end here.
    """
    gate = _cns_gate()
    return gate.GateChain(alpha=(PerimeterGate(registry), HealthGate(limits)))
