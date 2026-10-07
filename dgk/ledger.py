from __future__ import annotations

import copy
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

from .taxonomy import Event, Provenance, Snapshot


# CRYPTOGRAPHICALLY TAMPER-EVIDENT EVENT STORAGE LEDGER
# ============================================================
class HashChainStrategy(Protocol):
    def compute_hash(self, previous_hash: str, event: Event) -> str: ...


class Sha256Chain(HashChainStrategy):
    """Computes SHA-256 signatures over sequential state mutation matrices."""

    def compute_hash(self, previous_hash: str, event: Event) -> str:
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


class EventStore:
    """An append-only, hash-chained event store, kept separately per partition."""

    def __init__(self, hashing_strategy: Optional[HashChainStrategy] = None):
        self._partition_streams: Dict[str, List[Event]] = {}
        self._partition_heads: Dict[str, str] = {}
        self._hashing_strategy = hashing_strategy or Sha256Chain()

    def append_event(
        self,
        entity_id: str,
        event_type: str,
        delta: Dict[str, Any],
        provenance: Provenance,
    ) -> Tuple[Event, str]:
        stream = self._partition_streams.setdefault(entity_id, [])
        next_sequence_no = len(stream) + 1

        event_instance = Event(
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

    def get_events_since(self, entity_id: str, sequence_no: int) -> List[Event]:
        stream = self._partition_streams.get(entity_id, [])
        return [event for event in stream if event.sequence_no > sequence_no]


# ============================================================
# STATE PROJECTION REDUCERS & AUDIT PIPELINES
# ============================================================
class Reducer(Protocol):
    def apply_transition(
        self, context: Dict[str, Any], event: Event
    ) -> Dict[str, Any]: ...


class StateReducer:
    """Folds sequential transactional changes to yield updated state models."""

    def apply_transition(self, context: Dict[str, Any], event: Event) -> Dict[str, Any]:
        mutated_state = copy.deepcopy(context)
        if event.event_type == "telemetry_update":
            mutated_state["metrics"] = event.delta
        elif event.event_type == "escalation":
            mutated_state["escalation_logged"] = True
        elif event.event_type == "status_change":
            mutated_state["system_status"] = event.delta.get("status")
        return mutated_state


@dataclass(frozen=True)
class InvariantSet:
    manifest_id: str
    manifest_version: str
    invariants: Dict[
        str,
        Callable[[Mapping[str, Any], Event, Mapping[str, Any]], Tuple[bool, str]],
    ] = field(default_factory=dict)


def check_escalation_invariant(
    before: Mapping[str, Any], event: Event, after: Mapping[str, Any]
) -> Tuple[bool, str]:
    """Safety invariant: a CRITICAL status must have a logged escalation."""
    if after.get("system_status") == "CRITICAL" and not after.get(
        "escalation_logged", False
    ):
        return (
            False,
            "Transition constraint violation: critical state reached without "
            "an escalation entry.",
        )
    return True, "OK"


class TransitionChecker:
    """Simulates a transition and checks it against the invariants before commit."""

    def __init__(self, manifest: InvariantSet, reducer: Reducer) -> None:
        self._manifest = manifest
        self._reducer = reducer

    def verify_transition(
        self, before: Dict[str, Any], event: Event
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


class SnapshotPolicy(Protocol):
    def should_create_snapshot(self, event_delta: int) -> bool: ...


class EveryNEventsPolicy(SnapshotPolicy):
    def __init__(self, interval_limit: int):
        self._interval_limit = interval_limit

    def should_create_snapshot(self, event_delta: int) -> bool:
        return event_delta >= self._interval_limit


class StateMaterializer:
    """Rebuilds the current state from events, using cached snapshots where possible."""

    def __init__(
        self,
        store: EventStore,
        reducer: Reducer,
        policy: SnapshotPolicy = EveryNEventsPolicy(50),
    ) -> None:
        self._store = store
        self._reducer = reducer
        self._policy = policy
        self._snapshot_cache: Dict[str, Snapshot] = {}

    def materialize_state(self, entity_id: str) -> Mapping[str, Any]:
        snapshot = self._snapshot_cache.get(
            entity_id,
            Snapshot(entity_id=entity_id, last_sequence_no=0, context={}),
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
            self._snapshot_cache[entity_id] = Snapshot(
                entity_id=entity_id,
                last_sequence_no=unprocessed_events[-1].sequence_no,
                context=copy.deepcopy(running_context),
            )
        return MappingProxyType(running_context)


# ============================================================
