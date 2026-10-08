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
4. Commits the event to an in-memory ledger.
5. Checks the text for sycophantic phrasing and first-person identity
   language, and replaces a short list of jargon words. Findings are recorded.
   Nothing is blocked on this step.
6. Writes one JSON line to the audit file.

Breaches of the health limits (latency above 500, abort rate above 0.25, retry
rate above 2.0) reject the transaction. A rejected transaction writes nothing
to the ledger or the audit file.

## Known gaps

These are the gaps between the design and the code. Each one is confirmed by
reading the code. Tests do not cover them.

**Record and proof**
- The ledger exists only in memory. It is lost on restart, and there is no
  function to verify its hash chain.
- The audit file lines are not chained and not signed. Signing helpers exist
  but nothing calls them. Replaying the audit file reads lines and checks
  nothing.
- The audit line is written after the ledger commit. A crash between the two
  leaves a commit with no audit line.
- A rejected request leaves no record at all.

**Identity**
- Every transaction is recorded under the same fixed internal actor and
  policy. The caller is not identified or checked.
- The caller also chooses the partition name, so any caller can write to any
  partition.

**Concurrency**
- The name says "distributed." It is one process. Event appends are guarded by
  a lock, so concurrent calls cannot share a sequence number. The whole
  transaction is not atomic: the manifest check and the commit are separate
  steps.

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
- 53 tests pass and 9 documented gaps are marked as expected failures. CI runs the tests and the demo on Python 3.10 to 3.13.

## Running it

```bash
pip install -e .               # or: pip install -e ".[reservoir]"

python3 examples/run_kernel_demo.py   # commit, rejection, replay
python3 -m pytest tests/ -q           # 53 tests, 9 expected failures
```

```python
from dgk import Kernel

# log_path (or DGK_AUDIT_LOG) is required; the file is created owner-only (0600)
kernel = Kernel(log_path="audit.log")
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
)
# -> transaction_status COMMITTED, a block hash, a ledger sequence number,
#    and scrubbed text "We are using complete models."
```

## Modules

- `taxonomy.py`: regimes, telemetry payloads, provenance, events
- `serialization.py`: canonical JSON and helpers (see gaps on rounding)
- `audit.py`: owner-only audit file, HMAC helpers (not on the write path)
- `ledger.py`: in-memory hash-chained event store, reducer, invariants, snapshots
- `linguistics.py`: text checks and jargon normalization
- `stability.py`: running statistics, entropy, energy, regime classifier with hysteresis, optional reservoir
- `interceptors.py`: perimeter rules and the rule registry
- `kernel.py`: wires the pieces into one transaction

## Known open items

Caller identity, signed and chained audit records, a persistent ledger with a
verify step. None of these are built yet. Sequence numbers are now locked per
partition, and numbers are rounded to six decimal places before hashing.
