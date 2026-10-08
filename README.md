# DGK

DGK is a prototype governance kernel. It is a single-process Python library
that checks health telemetry and text output for each transaction, decides
whether to accept it, and writes a record of what happened.

**Status: prototype. Not production software.** It is a reconstruction. The
original repository was lost, and this code was rebuilt from a conversation
export. See `PROVENANCE.md` and `RECONSTRUCTION.md`.

## What it is for

The intent is a system that can prove afterward what it did and why. Two
design promises follow from that intent:

1. Current state is derived from the event record.
2. Every record is chained and signed, so editing history leaves evidence.

Only part of this is built. The gaps are listed below. Read the gaps before
you rely on the record for anything.

## What it does, per transaction

1. Reads five telemetry values (latency, abort rate, retry rate, load depth,
   determinism) and places the system in an operating regime. It escalates
   at once and recovers only after three calm readings in a row. This part
   works and is tested.
2. Rejects the request if the text contains the word "forbidden". A rejected
   request writes nothing to the ledger or the audit file. This is tested and
   is deliberate, but it means a refusal leaves no trace.
3. Checks a set of invariants. The only invariant can never fail (see gaps).
4. Commits the event to the ledger file, which is verified on every load.
5. Checks the text for sycophantic phrasing and first-person identity
   language, and replaces a short list of jargon words. Findings are recorded.
   Nothing is blocked on this step.
6. Writes one signed, chained JSON line to the audit file. A refused
   request writes one signed refusal line instead.

Breaches of the health limits (latency above 500, abort rate above 0.25, retry
rate above 2.0) reject the transaction. A rejected transaction writes nothing
to the ledger or the audit file.

## Known gaps

These are the gaps between the design and the code. Each one is confirmed by
reading the code. Tests do not cover them.

**Record and proof**
- OPEN: removing the newest ledger events is not detectable. The ledger is
  append-only and verified on load, and a tampered middle event or line is
  detected, but truncation at the end is not. Closing this needs a published
  head hash (an external anchor). Where that anchor lives is not yet decided.
- The audit line is written after the ledger commit. A crash between the two
  leaves a commit with no audit line.
- The audit key sits on the same machine as the trail. Anyone who can read
  the key can forge new records, so the trail proves tampering only against
  someone who lacks the key.

**Identity**
- Callers are checked. Each caller must present a token that matches a
  registered digest, and may write only to the partitions it was granted.
  Requests from anyone else are rejected before any state changes.
- The token is never stored. The registry keeps only a SHA-256 digest of it,
  so tokens must be long and random. The check is only as strong as the
  secrecy of those tokens; there is no key rotation or revocation yet.
- Refusals are signed and recorded, with the caller and the reason.

**Concurrency**
- The name says "distributed." It is one process. Event appends are guarded by
  a lock, and each whole transaction runs under one lock, so concurrent calls
  cannot share a sequence number or both pass the manifest check.

**Blocking and invariants**
- The only invariant (a critical state must have a logged escalation) can
  never fail. The kernel never creates a status change event, and the
  classifier never returns the top regime.
- The text check is advisory. It records findings but blocks nothing.

**Text checks**
- The sycophancy and identity checks are word-list heuristics. Scoring is per
  sentence, so a sycophantic paragraph can pass (pinned by a test as observed
  behavior).
- The jargon table is short and hand-written.

**Numbers and hashing**
- The entropy score adds five unlike quantities, so it is not a clean
  information measure.

**Other**
- The echo state reservoir is optional (needs numpy). The kernel never uses it.
- The version number 4.0.0 is inherited from the pasted original. It does not
  reflect a release history.

## What works and is tested

- The audit file is created owner-only and refuses a symlink at its path.
- Regime escalation and recovery, including the recovery streak.
- Rejected requests leave the ledger and audit file untouched.
- A healthy transaction commits and its text is normalized.
- A health breach rejects the transaction and writes nothing.
- 88 tests pass and 5 documented gaps are marked as expected failures. CI runs the tests and the demo on Python 3.10 to 3.13.

## Running it

```bash
pip install -e .               # or: pip install -e ".[reservoir]"

python3 examples/run_kernel_demo.py   # commit, rejection, replay
python3 -m pytest tests/ -q           # 88 tests, 5 expected failures
```

```python
from dgk import Kernel

# log_path (or DGK_AUDIT_LOG) is required; the file is created owner-only (0600)
kernel = Kernel(log_path="audit.log")
# token: a long random string you generate and keep secret (for example
# secrets.token_urlsafe(32)). Only its digest is stored.
# Register each caller once. Nothing can act until a caller is registered.
kernel.callers.register("ops-east", token, partitions=["region-us-east"])

result = kernel.process_transaction(
    partition_id="region-us-east",
    telemetry_map={
        "latency": 134.2,
        "abort_rate": 0.008,
        "reentry_rate": 0.04,
        "load_depth": 280.0,
        "determinism_index": 0.998,
    },
    text_payload="We are utilizing holistic paradigms.",
    caller_id="ops-east",
    caller_token=token,
)
# -> transaction_status COMMITTED, a block hash, a ledger sequence number,
#    and scrubbed text "We are using complete models."
```

## Modules

- `taxonomy.py`: regimes, telemetry payloads, provenance, events
- `serialization.py`: canonical JSON and helpers (see gaps on rounding)
- `audit.py`: owner-only, signed and chained audit trail, with its own key file
- `ledger.py`: hash-chained event store (append-only file, verified on load), reducer, invariants, snapshots
- `linguistics.py`: text checks and jargon normalization
- `stability.py`: running statistics, entropy, energy, regime classifier with hysteresis, optional reservoir
- `interceptors.py`: perimeter rules and the rule registry
- `identity.py`: caller tokens (digests only) and partition grants
- `kernel.py`: wires the pieces into one transaction

## Known open items

Nothing from the upgrade list is open. Done: sequence numbers locked per
partition, each transaction under one lock, numbers rounded to six decimal
places before hashing, callers checked by token and partition, the audit trail
signed and chained with refusals recorded, and the ledger persisted and
verified on load.

OPEN: an external anchor so that truncating the newest events is detectable.
Not built, and the choice of where the anchor is published is not yet made.
