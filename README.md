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

1. Checks the caller. Each caller presents a token that matches a registered
   digest and may write only to the partitions it was granted. Anything that
   is not a string is refused. This runs first, so an unauthorized request
   cannot change any state.
2. Validates the five telemetry values (latency, abort rate, retry rate, load
   depth, determinism). A value that is not a finite, non-negative number is
   refused. Booleans are refused too. The whole map is committed to the ledger,
   extra keys included, so anything in it that cannot be recorded (an object,
   a non-finite number, a non-string key, nesting past 8 levels, a cycle) is
   refused as well, and a refusal is written, not raised.
3. Places the system in an operating regime. It escalates at once and
   recovers only after three calm readings in a row.
4. Screens the text. A request containing the word "forbidden" is refused. The
   match survives case, invisible characters, lookalike Cyrillic and Greek
   letters, and punctuation or spaces inside the word.
5. Rejects the request if a health limit is breached (latency above 500, abort
   rate above 0.25, retry rate above 2.0).
6. Checks the invariants. The only invariant can never fail (see gaps).
7. Commits the event to the ledger file.
8. Checks the text for sycophantic phrasing and first-person identity
   language, and replaces a short list of jargon words. Findings are recorded.
   Nothing is blocked on this step.
9. Writes one signed, chained JSON line to the audit file.

Every refusal writes a signed line with the caller, the reason, and a cause
(IDENTITY, TELEMETRY_INVALID, PERIMETER, HEALTH_LIMIT, or MANIFEST). The same
cause is returned to the caller as `refusal_cause`. A refused request writes
nothing to the ledger.

The caller, partition and reason text in a refusal record is cut to 256
characters (with the original length and a digest), so a caller cannot choose
how large a signed record is. Refusals from callers who failed the identity
check also share a budget (60 per 60 seconds by default). Past the budget they
are counted, not written, and one signed `refusals_suppressed` line records
the count. Refusals from authorized callers are never suppressed.

## Restart and recovery

The record is what a restart is built from.

- **Regime.** Every audit line that reaches the classifier carries its
  reading, refused ones included, because a refused health breach still moved
  the regime. A new kernel replays them in order, so the regime, the recovery
  streak and the running statistics come back exactly. A trail written before
  this existed has no readings, and its kernel starts in NOMINAL.
- **Ledger against trail.** On start, each commit the trail signed must be in
  the ledger with the same hash. A ledger that was cut back, or rewritten with
  a recomputed chain, is refused with `LedgerAuditMismatch`.
- **Crash between ledger and audit.** One ledger commit with no audit line is
  the commit a crash interrupted. It is written to the trail as
  `reconciled_ledger_commit`. More than one is refused, because a crash cannot
  produce that.
- **Half-written last line.** An unfinished last line in the audit file or the
  ledger file is cut off, and the audit file records the cut as
  `recovered_torn_tail`. A whole record missing only its newline is kept.
  Damage anywhere earlier still stops the kernel, and says which record.
- **Anchor (optional).** Pass `anchor=` an object with `publish` and `latest`
  (see `anchor.py`). The kernel publishes each new head and refuses to start if
  the ledger lacks a head the anchor has seen. That is the only check that
  catches the ledger and the trail being cut back together.

Call `kernel.close()` when finished. It writes any pending refusal summary and
closes the files.

## Known gaps

These are the gaps between the design and the code. Each one is confirmed by
reading the code.

**Record and proof**
- OPEN: cutting back the ledger and the audit trail together is not detectable
  unless an anchor is configured. The mechanism is built. Where the anchor is
  published (another host, write-once storage, a second organization) is not
  decided, and none is configured by default. An anchor on the same disk adds
  almost nothing.
- Cutting back the newest audit line alone looks the same as the interrupted
  commit above, so it is reconciled, not refused. Two or more are refused.
- The audit key sits on the same machine as the trail. Anyone who can read
  the key can forge new records, so the trail proves tampering only against
  someone who lacks the key. Use `key_path` to keep the key elsewhere.
- The ledger's own chain is unkeyed SHA-256. Its protection against a rewrite
  comes from the signed audit trail, as described above.
- A refusal summary that has not been written when the process dies is lost.
  The individual lines up to the budget are not.

**Identity**
- The token is never stored. The registry keeps only a SHA-256 digest of it,
  so tokens must be long and random. The check is only as strong as the
  secrecy of those tokens.
- `revoke` and `rotate` take effect at once. The registry is in memory, so
  callers are registered again on every start.

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
- The perimeter, sycophancy and identity checks are word-list heuristics. A
  synonym or a different spelling of "forbidden" still passes. The perimeter
  can also match across a word break ("for bidden"); that is accepted.
- Flattery is flagged per segment, and also when three distinct markers appear
  anywhere in the text.
- The jargon table is short and hand-written.

**Numbers**
- The entropy score adds five unlike quantities, so it is not a clean
  information measure.

**Other**
- The echo state reservoir is optional (needs numpy). The kernel never uses it.
- The version number 4.0.0 is inherited from the pasted original. It does not
  reflect a release history.

## What works and is tested

- The audit file is created owner-only and refuses a symlink at its path.
- Regime escalation and recovery, and the regime surviving a restart.
- A commit, a refusal of each cause, and a health breach that writes nothing to the ledger.
- A cut-back or rewritten ledger, a crash between ledger and audit, and a torn last line.
- The anchor catching a joint cut-back, and a failing anchor being recorded.
- The unauthenticated flood being capped, and non-string credentials being refused.
- 201 tests pass and 1 documented gap is marked as an expected failure (a bare
  ledger file cannot see its own truncation; the kernel checks it). CI runs
  the tests and the demo on Python 3.10 to 3.13.

## Running it

```bash
pip install -e .               # or: pip install -e ".[reservoir]"

python3 examples/run_kernel_demo.py   # commit, rejection, replay
python3 -m pytest tests/ -q           # 201 tests, 1 expected failure
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
- `audit.py`: owner-only, signed and chained audit trail, with its own key file; cuts a torn last line
- `ledger.py`: hash-chained event store (append-only file, verified on load), reducer, invariants, snapshots
- `linguistics.py`: text checks and jargon normalization
- `stability.py`: running statistics, entropy, energy, regime classifier with hysteresis, optional reservoir
- `interceptors.py`: perimeter rules and the rule registry
- `identity.py`: caller tokens (digests only), partition grants, revoke and rotate
- `budget.py`: the cap on refusals from callers who failed the identity check
- `anchor.py`: the optional external anchor for ledger heads
- `kernel.py`: wires the pieces into one transaction

## Known open items

OPEN: choosing where an anchor is published. The mechanism is built and tested;
without a configured anchor, cutting back the ledger and the trail together is
not detectable.
