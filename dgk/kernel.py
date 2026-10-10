from __future__ import annotations

import dataclasses
import hashlib
import math
import os
import threading
import time
from typing import Any, Dict, Optional

from .anchor import AnchorMismatch, HeadAnchor
from .audit import AuditLog
from .budget import RefusalBudget
from .identity import CallerRegistry
from .interceptors import (
    ForbiddenWordRule,
    RuleRegistry,
    RequestBuilder,
    HealthLimitCheck,
)
from .ledger import (
    StateReducer,
    StateMaterializer,
    EventStore,
    TransitionChecker,
    InvariantSet,
    check_escalation_invariant,
)
from .linguistics import TextNormalizer, TextChecker
from .stability import RegimeTracker
from .taxonomy import Provenance, TelemetryReading


# GOVERNANCE CENTRAL KERNEL CONCURRENCY ENGINE
# ============================================================
class TelemetryError(ValueError):
    """A telemetry field is missing a usable value: not a number, not finite, or negative."""


class LedgerAuditMismatch(ValueError):
    """The ledger does not agree with the signed audit trail."""


#: Longest caller, partition or reason text copied into a refusal record. Longer
#: text is cut and replaced by its length and a digest, so a caller who has
#: proved nothing cannot choose how large a signed record is.
MAX_RECORDED_TEXT = 256


def _clip(value: Any) -> str:
    text = str(value)
    if len(text) <= MAX_RECORDED_TEXT:
        return text
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{text[:MAX_RECORDED_TEXT]}...[{len(text)} chars, sha256 {digest}]"


class Kernel:
    """Combines the rule checks, the ledger, and the stability tracker in one place."""

    def __init__(
        self,
        log_path: Optional[str] = None,
        callers: Optional[CallerRegistry] = None,
        key_path: Optional[str] = None,
        anchor: Optional[HeadAnchor] = None,
        refusal_budget: Optional[RefusalBudget] = None,
    ) -> None:
        # No shared default: the old /tmp/gov4_central_ssot.log was readable
        # and pre-creatable by any local user. The caller (or DGK_AUDIT_LOG)
        # must choose where the audit trail lives.
        log_path = log_path or os.environ.get("DGK_AUDIT_LOG")
        if not log_path:
            raise ValueError("pass log_path= or set DGK_AUDIT_LOG")
        self.audit_logger = AuditLog(log_path, key_path)
        # Empty by default: no caller can act until one is registered.
        self.callers = callers or CallerRegistry()
        self.ledger_store = EventStore(path=log_path + ".ledger")
        self.state_reducer = StateReducer()
        self.materialization_runtime = StateMaterializer(
            self.ledger_store, self.state_reducer
        )
        self.linguistic_compliance_engine = TextChecker()
        self.text_normalizer = TextNormalizer()
        self.hysteresis_chassis = RegimeTracker()
        # One transaction at a time: the manifest check and the commit must
        # see the same state, or two requests could both pass the check.
        self._transaction_lock = threading.Lock()

        self.interceptor_registry = RuleRegistry()
        self.interceptor_registry.register(ForbiddenWordRule())
        self.boundary_barrier = HealthLimitCheck()

        core_validation_manifest = InvariantSet(
            manifest_id="CENTRAL_ORCHESTRATION_MANIFEST",
            manifest_version="v1.0",
            invariants={"check_escalation_invariant": check_escalation_invariant},
        )
        self.transition_auditor = TransitionChecker(
            core_validation_manifest, self.state_reducer
        )
        # Refusals from callers who failed the identity check are capped.
        self._identity_budget = refusal_budget or RefusalBudget()
        self.anchor = anchor
        try:
            self._restore_from_record()
        except Exception:
            # A kernel that refuses to start must not leave its files open.
            self.audit_logger.close_stream()
            self.ledger_store.close()
            raise

    def _restore_from_record(self) -> None:
        """Rebuild what a restart would otherwise forget, from the signed trail.

        The regime depends on every reading the classifier saw, so each audit
        record that reaches the classifier carries its reading and they are
        replayed in order. The ledger is then checked against the trail and
        against the anchor, if there is one.
        """
        records = self.audit_logger.replay_log_history()
        for record in records:
            reading = record.get("telemetry_reading")
            if reading is not None:
                self.hysteresis_chassis.process_telemetry_step(
                    TelemetryReading(**reading)
                )
        self._check_ledger_against_trail(records)
        self._check_ledger_against_anchor()

    def _check_ledger_against_trail(self, records) -> None:
        """Every commit the trail signed must be in the ledger with the same hash.

        Catches a ledger that was rewritten or cut back while the trail still
        remembers the commits. A commit that reached the ledger just before a
        crash, with no audit line yet, is written to the trail now. More than
        one is not a crash, so it is refused.
        """
        audited: Dict[str, int] = {}
        for record in records:
            partition = record.get("partition_id")
            sequence = record.get("stream_sequence_index")
            head = record.get("blockchain_hash_head")
            if partition is None or sequence is None or head is None:
                continue
            if self.ledger_store.hash_at(partition, sequence) != head:
                raise LedgerAuditMismatch(
                    f"ledger does not contain commit {sequence} of partition "
                    f"{_clip(partition)!r} as the audit trail signed it; the ledger "
                    "was cut back or rewritten"
                )
            audited[partition] = max(sequence, audited.get(partition, 0))
        missing = [
            (partition, sequence)
            for partition in self.ledger_store.partitions()
            for sequence in range(
                audited.get(partition, 0) + 1,
                self.ledger_store.event_count(partition) + 1,
            )
        ]
        if len(missing) > 1:
            raise LedgerAuditMismatch(
                f"{len(missing)} ledger events have no audit record; at most "
                "one can be the commit a crash interrupted"
            )
        for partition, sequence in missing:
            event = self.ledger_store.get_events_since(partition, sequence - 1)[0]
            self.audit_logger.append_record(
                {
                    "event": "reconciled_ledger_commit",
                    "partition_id": partition,
                    "caller_id": event.provenance.actor_id,
                    "timestamp": time.time(),
                    "blockchain_hash_head": self.ledger_store.hash_at(
                        partition, sequence
                    ),
                    "stream_sequence_index": sequence,
                }
            )

    def _check_ledger_against_anchor(self) -> None:
        if self.anchor is None:
            return
        for partition, (sequence, head) in self.anchor.latest().items():
            if self.ledger_store.hash_at(partition, sequence) != head:
                raise AnchorMismatch(
                    f"ledger no longer holds commit {sequence} of partition "
                    f"{_clip(partition)!r} that the anchor recorded"
                )

    def close(self) -> None:
        """Write any pending refusal summary and close the files."""
        self._write_suppressed_summary(self._identity_budget.take_all())
        self.audit_logger.close_stream()
        self.ledger_store.close()

    def _write_suppressed_summary(self, count: int) -> None:
        if count:
            self.audit_logger.append_record(
                {
                    "event": "refusals_suppressed",
                    "cause": "IDENTITY",
                    "count": count,
                    "timestamp": time.time(),
                }
            )

    def process_transaction(
        self,
        partition_id: str,
        telemetry_map: Dict[str, Any],
        text_payload: str,
        caller_id: str,
        caller_token: str,
    ) -> Dict[str, Any]:
        """Run one transaction through every gate, one at a time."""
        with self._transaction_lock:
            return self._run_transaction(
                partition_id, telemetry_map, text_payload, caller_id, caller_token
            )

    def _refuse(
        self,
        partition_id: str,
        caller_id: str,
        reason: str,
        cause: str,
        telemetry_metrics: Optional[Dict[str, Any]] = None,
        reading: Optional[TelemetryReading] = None,
    ) -> Dict[str, Any]:
        """Record a refusal in the signed audit trail, then return the rejection.

        Identity refusals come from callers who have proved nothing, so they
        share a budget; past it they are counted, not written.
        """
        if cause == "IDENTITY":
            written = self._identity_budget.admit()
            self._write_suppressed_summary(self._identity_budget.take_rolled())
        else:
            written = True
        if written:
            record: Dict[str, Any] = {
                "event": "refused",
                "partition_id": _clip(partition_id),
                "caller_id": _clip(caller_id),
                "timestamp": time.time(),
                "reason": _clip(reason),
                "cause": cause,
            }
            if reading is not None:
                record["telemetry_reading"] = dataclasses.asdict(reading)
            self.audit_logger.append_record(record)
        result: Dict[str, Any] = {
            "transaction_status": "REJECTED",
            "exception_details": reason,
            "refusal_cause": cause,
        }
        if telemetry_metrics is not None:
            result["telemetry_metrics"] = telemetry_metrics
        return result

    def _run_transaction(
        self,
        partition_id: str,
        telemetry_map: Dict[str, Any],
        text_payload: str,
        caller_id: str,
        caller_token: str,
    ) -> Dict[str, Any]:
        # Checked first, so an unauthorized request cannot change regime state.
        if not self.callers.authorizes(caller_id, caller_token, partition_id):
            return self._refuse(
                partition_id,
                caller_id,
                "caller is not authorized for this partition",
                "IDENTITY",
            )

        """Steps: read telemetry and classify the regime, screen the text at the
        perimeter, verify the transition against the manifest, commit to the
        ledger, check and normalize the text, then write the audit record.
        """
        # Validated before it reaches the classifier: one NaN would corrupt the running
        # statistics for the life of the process, and an infinity would raise out of the call
        # before any refusal was recorded.
        try:
            telemetry = self._read_telemetry(telemetry_map)
        except TelemetryError as exc:
            return self._refuse(partition_id, caller_id, str(exc), "TELEMETRY_INVALID")
        stability_metrics = self.hysteresis_chassis.process_telemetry_step(telemetry)
        boundary_pass, boundary_faults = self.boundary_barrier.verify_bounds(telemetry)

        perimeter_check = self._check_perimeter(text_payload)
        if not perimeter_check.passed:
            return self._refuse(
                partition_id,
                caller_id,
                perimeter_check.details,
                "PERIMETER",
                telemetry_metrics=stability_metrics,
                reading=telemetry,
            )

        if not boundary_pass:
            return self._refuse(
                partition_id,
                caller_id,
                f"Health limits breached: {boundary_faults}",
                "HEALTH_LIMIT",
                telemetry_metrics=stability_metrics,
                reading=telemetry,
            )

        provenance_block = Provenance(
            actor_id=caller_id,
            policy_id="CENTRAL_ORCHESTRATION_MANIFEST",
            justification="Automated ingestion block commit",
        )
        transition_verified, invariant_breaches = self._verify_transition(
            partition_id, telemetry_map, provenance_block
        )
        if not transition_verified:
            return self._refuse(
                partition_id,
                caller_id,
                f"Manifest contract breached: {invariant_breaches}",
                "MANIFEST",
                reading=telemetry,
            )

        committed_block, blockchain_head_hash = self.ledger_store.append_event(
            partition_id, "telemetry_update", telemetry_map, provenance_block
        )

        linguistic_anomalies = self.linguistic_compliance_engine.validate_text_stream(
            text_payload
        )
        scrubbed_text_output = self.text_normalizer.normalize(text_payload)

        self.audit_logger.append_record(
            {
                "partition_id": partition_id,
                "caller_id": caller_id,
                "timestamp": time.time(),
                "blockchain_hash_head": blockchain_head_hash,
                "stream_sequence_index": committed_block.sequence_no,
                "operational_regime": stability_metrics["operational_regime"],
                "boundary_pass": boundary_pass,
                "boundary_faults": boundary_faults,
                "linguistic_anomalies": linguistic_anomalies,
                "telemetry_reading": dataclasses.asdict(telemetry),
            }
        )

        result = {
            "transaction_status": "COMMITTED",
            "scrubbed_text": scrubbed_text_output,
            "compliance_anomalies": linguistic_anomalies,
            "stability_profile": stability_metrics,
            "ledger_sequence": committed_block.sequence_no,
            "block_hash": blockchain_head_hash,
        }
        if self.anchor is not None:
            result["anchor_published"] = self._publish_anchor(
                partition_id, committed_block.sequence_no, blockchain_head_hash
            )
        return result

    def _publish_anchor(self, partition_id: str, sequence_no: int, head: str) -> bool:
        """Tell the anchor about the new head. A failure is recorded, not hidden."""
        try:
            self.anchor.publish(partition_id, sequence_no, head)
        except Exception as exc:  # the commit stands; the gap must be on record
            self.audit_logger.append_record(
                {
                    "event": "anchor_publish_failed",
                    "partition_id": partition_id,
                    "sequence_no": sequence_no,
                    "reason": _clip(exc),
                    "timestamp": time.time(),
                }
            )
            return False
        return True

    @staticmethod
    def _read_telemetry(telemetry_map: Dict[str, Any]) -> TelemetryReading:
        """Coerce the raw telemetry map to floats, with defaults for missing keys.

        Raises TelemetryError for a value that is not a finite, non-negative number.
        """
        defaults = (
            ("latency", 0.0),
            ("abort_rate", 0.0),
            ("reentry_rate", 0.0),
            ("load_depth", 0.0),
            ("determinism_index", 1.0),
        )
        values: Dict[str, float] = {}
        for name, default in defaults:
            raw = telemetry_map.get(name, default)
            if isinstance(raw, bool):
                # float(True) is 1.0; a flag is not a measurement.
                raise TelemetryError(f"telemetry {name} is not a number")
            try:
                value = float(raw)
            except (TypeError, ValueError, OverflowError):
                raise TelemetryError(f"telemetry {name} is not a number") from None
            if not math.isfinite(value) or value < 0:
                raise TelemetryError(f"telemetry {name} is not a finite non-negative number")
            values[name] = value
        return TelemetryReading(**values)

    def _check_perimeter(self, text_payload: str):
        """Run the text through the forbidden-word perimeter rules."""
        normalized_payload = {
            "text": text_payload,
            "messages": [{"role": "user", "content": text_payload}],
        }
        governance_context = RequestBuilder.normalize(normalized_payload)
        return self.interceptor_registry.evaluate(governance_context)

    def _verify_transition(
        self,
        partition_id: str,
        telemetry_map: Dict[str, Any],
        provenance_block: Provenance,
    ):
        """Simulate the event on a scratch store and check it against the manifest.

        Nothing is written to the real ledger here. Returns (verified, breaches).
        """
        active_state_view = dict(
            self.materialization_runtime.materialize_state(partition_id)
        )
        simulation_store = EventStore()
        simulated_event, _ = simulation_store.append_event(
            partition_id, "telemetry_update", telemetry_map, provenance_block
        )
        return self.transition_auditor.verify_transition(
            active_state_view, simulated_event
        )


# ============================================================
