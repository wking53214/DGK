from dgk.ledger import HASH_FLOAT_PRECISION, Sha256Chain
from dgk.taxonomy import Event, Provenance

PROVENANCE = Provenance(actor_id="a", policy_id="p", justification="j")


def make_event(delta):
    return Event(
        event_id="fixed-id",
        entity_id="p",
        sequence_no=1,
        event_type="telemetry_update",
        delta=delta,
        provenance=PROVENANCE,
    )


def test_precision_is_six_decimal_places():
    assert HASH_FLOAT_PRECISION == 6


def test_differences_below_the_old_precision_now_hash_differently():
    chain = Sha256Chain()
    a = chain.compute_hash("GENESIS", make_event({"latency": 0.1 + 0.2}))
    b = chain.compute_hash("GENESIS", make_event({"latency": 0.3}))
    assert a != b


def test_differences_at_the_precision_hash_differently():
    chain = Sha256Chain()
    a = chain.compute_hash("GENESIS", make_event({"latency": 0.1234564}))
    b = chain.compute_hash("GENESIS", make_event({"latency": 0.1234574}))
    assert a != b


def test_stored_event_keeps_full_precision():
    event = make_event({"latency": 0.1 + 0.2})
    Sha256Chain().compute_hash("GENESIS", event)
    assert event.delta["latency"] == 0.1 + 0.2


# ---- Exact values, with older ledgers still readable ------------------------


def _old_hash(previous, event):
    """The hash the ledger wrote before the exact-value change: rounded numbers, no version."""
    import hashlib
    import json

    from dgk.serialization import round_floats

    payload = {
        "previous_hash": previous,
        "event_id": event.event_id,
        "entity_id": event.entity_id,
        "sequence_no": event.sequence_no,
        "event_type": event.event_type,
        "delta": round_floats(event.delta, HASH_FLOAT_PRECISION),
        "provenance": {"actor_id": "a", "policy_id": "p", "justification": "j"},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def test_an_old_rounded_hash_is_still_accepted_for_the_event_that_carries_it():
    chain = Sha256Chain()
    event = make_event({"latency": 134.2})
    assert chain.matches("GENESIS", event, _old_hash("GENESIS", event))


def test_an_old_hash_does_not_accept_a_change_past_the_sixth_place_that_was_never_rounded_away():
    chain = Sha256Chain()
    # A new event is hashed on exact values. Changing it past the sixth place must not verify.
    event = make_event({"latency": 134.2})
    stored = chain.compute_hash("GENESIS", event)
    event.delta["latency"] = 134.2000004
    assert not chain.matches("GENESIS", event, stored)


def test_a_new_hash_cannot_be_passed_off_as_an_old_one():
    chain = Sha256Chain()
    event = make_event({"latency": 134.2})
    assert chain.compute_hash("GENESIS", event) != _old_hash("GENESIS", event)
