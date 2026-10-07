from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

from .audit import generate_hmac_signature
from .serialization import (
    canonicalize_dictionary,
    filter_private_keys,
    normalize_numeric_precision,
)
from .taxonomy import NormalizedEvent, OperationProvenance, StateSnapshot


# CRYPTOGRAPHICALLY TAMPER-EVIDENT EVENT STORAGE LEDGER
# ============================================================
class CryptographicHashChainStrategy(Protocol):
    def compute_hash(self, previous_hash: str, event: NormalizedEvent) -> str: ...


class SHA256EventChaining(CryptographicHashChainStrategy):
    """Computes SHA-256 signatures over sequential state mutation matrices."""

    def compute_hash(self, previous_hash: str, event: NormalizedEvent) -> str:
        payload = {
            "previous_hash": previous_hash,
            "event_id": event.event_id,
            "entity_id": event.entity_id,
            "sequence_no": event.sequence_no,
            "event_type": event.event_type,
            "delta": event.delta,
            "provenance": {
                "actor_id": event.provenance.actor_id,
                "policy_id": event.provenance.policy_id,
                "justification": event.provenance.justification,
            },
        }
        serialized_payload = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(serialized_payload).hexdigest()


class PartitionedEventStore:
    """Append-only block ledger storing sequential state changes per entity partition."""

    def __init__(
        self, hashing_strategy: Optional[CryptographicHashChainStrategy] = None
    ):
        self._partition_streams: Dict[str, List[NormalizedEvent]] = {}
        self._partition_heads: Dict[str, str] = {}
        self._hashing_strategy = hashing_strategy or SHA256EventChaining()

    def append_event(
        self,
        entity_id: str,
        event_type: str,
        delta: Dict[str, Any],
        provenance: OperationProvenance,
    ) -> Tuple[NormalizedEvent, str]:
        stream = self._partition_streams.setdefault(entity_id, [])
        next_sequence_no = len(stream) + 1

        event_instance = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            entity_id=entity_id,
            sequence_no=next_sequence_no,
            event_type=event_type,
            delta=copy.deepcopy(delta),
            provenance=provenance,
        )

        genesis_hash = self._partition_heads.get(entity_id, "GENESIS")
        computed_hash = self._hashing_strategy.compute_hash(
            genesis_hash, event_instance
        )

        stream.append(event_instance)
        self._partition_heads[entity_id] = computed_hash
        return event_instance, computed_hash

    def get_events_since(
        self, entity_id: str, sequence_no: int
    ) -> List[NormalizedEvent]:
        stream = self._partition_streams.get(entity_id, [])
        return [event for event in stream if event.sequence_no > sequence_no]


# ============================================================
# STATE PROJECTION REDUCERS & AUDIT PIPELINES
# ============================================================
class StateStreamReducer(Protocol):
    def apply_transition(
        self, context: Dict[str, Any], event: NormalizedEvent
    ) -> Dict[str, Any]: ...


class CoreGovernanceReducer:
    """Folds sequential transactional changes to yield updated state models."""

    def apply_transition(
        self, context: Dict[str, Any], event: NormalizedEvent
    ) -> Dict[str, Any]:
        mutated_state = copy.deepcopy(context)
        if event.event_type == "telemetry_update":
            mutated_state["metrics"] = event.delta
        elif event.event_type == "escalation":
            mutated_state["escalation_logged"] = True
        elif event.event_type == "status_change":
            mutated_state["system_status"] = event.delta.get("status")
        return mutated_state


@dataclass(frozen=True)
class ValidationManifest:
    manifest_id: str
    manifest_version: str
    invariants: Dict[
        str,
        Callable[
            [Mapping[str, Any], NormalizedEvent, Mapping[str, Any]], Tuple[bool, str]
        ],
    ] = field(default_factory=dict)


def verify_critical_escalation_constraint(
    before: Mapping[str, Any], event: NormalizedEvent, after: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Safety Invariant: Verifies that status changes to CRITICAL generate audit trails."""
    if after.get("system_status") == "CRITICAL" and not after.get(
        "escalation_logged", False
    ):
        return (
            False,
            "Transition Constraint Violation: Critical state reached without accompanying escalation entry.",
        )
    return True, "OK"


class StateTransitionAuditor:
    """Simulates transformations to audit candidate blocks against runtime invariants."""

    def __init__(
        self, manifest: ValidationManifest, reducer: StateStreamReducer
    ) -> None:
        self._manifest = manifest
        self._reducer = reducer

    def verify_transition(
        self, before: Dict[str, Any], event: NormalizedEvent
    ) -> Tuple[bool, List[str]]:
        simulated_state = self._reducer.apply_transition(before, event)
        before_view = MappingProxyType(before)
        after_view = MappingProxyType(simulated_state)
        transition_errors = []

        for identifier, invariant_callable in self._manifest.invariants.items():
            success, message = invariant_callable(before_view, event, after_view)
            if not success:
                transition_errors.append(f"{identifier}: {message}")
        return len(transition_errors) == 0, transition_errors


class CheckpointPolicy(Protocol):
    def should_create_snapshot(self, event_delta: int) -> bool: ...


class UniformIntervalSnapshotPolicy(CheckpointPolicy):
    def __init__(self, interval_limit: int):
        self._interval_limit = interval_limit

    def should_create_snapshot(self, event_delta: int) -> bool:
        return event_delta >= self._interval_limit


class MaterializationRuntime:
    """Tracks system states by combining cached historical checkpoints and delta updates."""

    def __init__(
        self,
        store: PartitionedEventStore,
        reducer: StateStreamReducer,
        policy: CheckpointPolicy = UniformIntervalSnapshotPolicy(50),
    ) -> None:
        self._store = store
        self._reducer = reducer
        self._policy = policy
        self._snapshot_cache: Dict[str, StateSnapshot] = {}

    def materialize_state(self, entity_id: str) -> Mapping[str, Any]:
        snapshot = self._snapshot_cache.get(
            entity_id,
            StateSnapshot(entity_id=entity_id, last_sequence_no=0, context={}),
        )
        running_context = copy.deepcopy(snapshot.context)
        unprocessed_events = self._store.get_events_since(
            entity_id, snapshot.last_sequence_no
        )

        for event in unprocessed_events:
            running_context = self._reducer.apply_transition(running_context, event)

        if unprocessed_events and self._policy.should_create_snapshot(
            len(unprocessed_events)
        ):
            self._snapshot_cache[entity_id] = StateSnapshot(
                entity_id=entity_id,
                last_sequence_no=unprocessed_events[-1].sequence_no,
                context=copy.deepcopy(running_context),
            )
        return MappingProxyType(running_context)


# ============================================================
