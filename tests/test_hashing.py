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


def test_differences_below_the_precision_hash_the_same():
    chain = Sha256Chain()
    a = chain.compute_hash("GENESIS", make_event({"latency": 0.1 + 0.2}))
    b = chain.compute_hash("GENESIS", make_event({"latency": 0.3}))
    assert a == b


def test_differences_at_the_precision_hash_differently():
    chain = Sha256Chain()
    a = chain.compute_hash("GENESIS", make_event({"latency": 0.1234564}))
    b = chain.compute_hash("GENESIS", make_event({"latency": 0.1234574}))
    assert a != b


def test_stored_event_keeps_full_precision():
    event = make_event({"latency": 0.1 + 0.2})
    Sha256Chain().compute_hash("GENESIS", event)
    assert event.delta["latency"] == 0.1 + 0.2
