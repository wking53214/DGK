from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Tuple

from .audit import open_private_append
from .serialization import round_floats
from .taxonomy import Event, Provenance, Snapshot

# Numbers in an event's data are rounded to this many decimal places before
# hashing, so the same reading always produces the same hash. The stored
# event keeps full precision. Verifiers must apply the same rounding.
HASH_FLOAT_PRECISION = 6


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
            "delta": round_floats(event.delta, HASH_FLOAT_PRECISION),
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

    def __init__(
        self,
        hashing_strategy: Optional[HashChainStrategy] = None,
        path: Optional[str] = None,
    ):
        self._partition_streams: Dict[str, List[Event]] = {}
        self._partition_heads: Dict[str, str] = {}
        self._partition_hashes: Dict[str, List[str]] = {}
        self._hashing_strategy = hashing_strategy or Sha256Chain()
        # With a path, every event is appended to an owner-only file, and the
        # file is verified and loaded on startup. Without one, the store is
        # memory only.
        self._path = path
        self.recovered_bytes = 0
        self._file = open_private_append(path) if path else None
        if self._file is not None:
            self.recovered_bytes = self._repair_torn_tail()
            self._load()
        # Guards sequence numbering and the head hash so concurrent appends
        # to one partition cannot share a sequence number or fork the chain.
        self._lock = threading.Lock()

    def append_event(
        self,
        entity_id: str,
        event_type: str,
        delta: Dict[str, Any],
        provenance: Provenance,
    ) -> Tuple[Event, str]:
        with self._lock:
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

            if self._file is not None:
                # Write first: if the write fails, nothing changes in memory.
                record = {
                    "event_id": event_instance.event_id,
                    "entity_id": event_instance.entity_id,
                    "sequence_no": event_instance.sequence_no,
                    "event_type": event_instance.event_type,
                    "delta": event_instance.delta,
                    "actor_id": provenance.actor_id,
                    "policy_id": provenance.policy_id,
                    "justification": provenance.justification,
                    "hash": computed_hash,
                }
                self._file.write(json.dumps(record, sort_keys=True) + "\n")
                self._file.flush()

            stream.append(event_instance)
            self._partition_hashes.setdefault(entity_id, []).append(computed_hash)
            self._partition_heads[entity_id] = computed_hash
            return event_instance, computed_hash

    def verify_chain(self, entity_id: str) -> bool:
        """Recompute one partition's hash chain from its events. True if intact."""
        previous = "GENESIS"
        stream = self._partition_streams.get(entity_id, [])
        hashes = self._partition_hashes.get(entity_id, [])
        for index, (event, stored) in enumerate(zip(stream, hashes), start=1):
            if event.sequence_no != index:
                return False
            previous = self._hashing_strategy.compute_hash(previous, event)
            if previous != stored:
                return False
        return len(stream) == len(hashes)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def partitions(self) -> List[str]:
        return list(self._partition_streams)

    def event_count(self, entity_id: str) -> int:
        return len(self._partition_streams.get(entity_id, []))

    def hash_at(self, entity_id: str, sequence_no: int) -> Optional[str]:
        """The chain hash stored for one event, or None if there is no such event."""
        hashes = self._partition_hashes.get(entity_id, [])
        if 1 <= sequence_no <= len(hashes):
            return hashes[sequence_no - 1]
        return None

    def _repair_torn_tail(self) -> int:
        """Drop an unfinished last line left by a crash. Returns bytes removed.

        The line is written before memory changes, so an unfinished line is an
        event that never committed. A last line that is whole JSON but lacks
        its newline is kept, and the chain check in `_load` still applies.
        """
        self._file.flush()
        with open(self._path, "rb") as reader:
            data = reader.read()
        if not data or data.endswith(b"\n"):
            return 0
        cut = data.rfind(b"\n") + 1
        tail = data[cut:]
        try:
            json.loads(tail.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            os.truncate(self._path, cut)
            return len(tail)
        self._file.write("\n")
        self._file.flush()
        return 0

    def _load(self) -> None:
        """Rebuild partitions from the file, refusing a file with a broken chain."""
        self._file.seek(0)
        for line in self._file:
            if not line.strip():
                continue
            record = json.loads(line)
            event = Event(
                event_id=record["event_id"],
                entity_id=record["entity_id"],
                sequence_no=record["sequence_no"],
                event_type=record["event_type"],
                delta=record["delta"],
                provenance=Provenance(
                    actor_id=record["actor_id"],
                    policy_id=record["policy_id"],
                    justification=record["justification"],
                ),
            )
            self._partition_streams.setdefault(event.entity_id, []).append(event)
            self._partition_hashes.setdefault(event.entity_id, []).append(
                record["hash"]
            )
        for entity_id in self._partition_streams:
            if not self.verify_chain(entity_id):
                raise ValueError(f"ledger chain is broken for partition {entity_id!r}")
            self._partition_heads[entity_id] = self._partition_hashes[entity_id][-1]

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
