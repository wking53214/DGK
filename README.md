# DGK

DGK is a prototype governance kernel. It is a single-process Python library
that checks health telemetry and text output for each transaction, decides
whether to accept it, and writes a record of what happened.

**Status: prototype. Not production software.** It is a reconstruction. The
original repository was lost, and this code was rebuilt from a conversation
export. See `PROVENANCE.md` and `RECONSTRUCTION.md`.

## Role Within ≡TACK

- **What it is.** A single-process prototype kernel: per transaction it checks health telemetry and text, decides to commit or refuse, and writes a hash-chained ledger and a signed audit trail.
- **Authority matrix.** Evaluation (word-list and threshold checks), enforcement of its own accept or refuse decision inside the process, authentication of registered callers by token digest, and evidence generation (ledger plus signed audit). Verification of its own record on restart. It does not define policy beyond its built-in rules.
- **Does not own.** Distributed agreement (it is one process), production custody, or truth of the text it checks.
- **Depends on.** The standard library for the kernel; numpy is optional and the kernel never uses it; CNS is optional (see "Optional CNS connection").
- **Depended on by.** UNKNOWN (not inspected here).
- **Fail behavior.** Closed on refusals it implements (a refusal writes its cause; a health breach writes nothing to the ledger). Open on missing telemetry: a reading that is absent is treated as healthy (step 2 below). The text check is advisory and blocks nothing. The audit key sits on the same machine as the trail, so tampering is only evident against someone without the key, and a joint cut-back of ledger and audit is undetectable without an anchor, which is not configured by default.

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
   refused as well, and a refusal is written, not raised. A reading that is
   missing from the map is not refused. It is filled in with a healthy default
   (0 for latency, abort rate, retry rate and load depth; 1.0 for determinism),
   so an empty map, or one whose keys are misspelled, is read as a healthy
   system and committed (EXECUTED 2026-11-18: an empty map, and a map holding
   only `Latency: 9999`, were both COMMITTED).
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

## Optional CNS connection

DGK does not need CNS. It has no runtime dependency, nothing in the package imports CNS when it loads, and the kernel never imports it (`tests/test_cns_independence.py` checks this with CNS blocked). `dgk/cns_connector.py` is the one place that knows CNS exists. Install it from a clone with `pip install -e ".[cns]"`, or with `pip install "dgk[cns] @ git+https://github.com/wking53214/DGK.git"`. The bare form `pip install 'dgk[cns]'` does not work, because no package named `dgk` is published (EXECUTED 2026-11-18). The connector's error message prints the install-from-repository form. Without CNS, building a gate raises `CnsNotInstalled` and nothing else changes.

It offers two pure checks from the kernel as gates in CNS's shared gate contract (`cns.gate`), both at the `ALPHA` end because they judge a request before anything is committed:

| Gate | What it runs | PASS | not PASS |
|---|---|---|---|
| `PerimeterGate` | the perimeter rules (by default the forbidden-sequence screen) over the request text, or over every string in every field of a request mapping (`text`, `messages`, `metadata`, any other key, at any depth) | no rule rejects | `TERMINAL_BREACH` (a forbidden sequence does not become allowed by asking again) |
| `HealthGate` | the health limits over the five telemetry values | every limit holds | `RETRY` for a breached limit (load eases); `TERMINAL_BREACH`, unbound, for telemetry the kernel would refuse |

Each verdict is bound with `cns.gate.subject_digest` to what the check read: the request text (`{"text": ...}`), the whole request mapping (`{"request": ...}`), or the five readings. A verdict on one request does not bind to another. A request field the gate cannot read (bytes, an object, a non-text key, a request that contains itself) is an unbound `TERMINAL_BREACH`, and `PerimeterGate` refuses an empty rule registry with `ValueError`.

Asking a gate is not submitting a transaction. The gates do not touch the kernel, the regime tracker, the ledger or the audit trail, whereas a real transaction moves the regime on every reading it classifies. `tests/test_cns_connector.py` runs the gates and a real kernel over the same requests and checks they agree about what happens.

DGK has only the input end, so `cns_chain().complete()` is `False` by design. A repository with an `OMEGA` gate (DIT judges generated text) completes the chain.

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
- The signature on an audit line does not cover any field whose name starts
  with an underscore. The kernel writes no such field. One added to a signed
  line afterwards (for example `_approved_by`) is not noticed on restart, while
  a change to any signed field is refused (EXECUTED 2026-11-18).

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
- The ledger rounds every number to six decimal places before hashing. A
  stored reading changed past the sixth place (134.2 to 134.2000004 in the
  ledger file) did not break the chain and the kernel started; a change in the
  second place was refused (EXECUTED 2026-11-18). This is the rounding gap the
  module list below points to. It was missing from this section.

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
- EXECUTED 2026-11-18 at `e6874ba`, Python 3.13, fresh environments. The command under
  "Running it" (this package and pytest, nothing else): 211 passed, 2 skipped, 1 expected
  failure (a bare ledger file cannot see its own truncation; the kernel checks it). The two
  skipped modules need CNS. With the `cns` extra and `DGK_REQUIRE_CNS=1`, as CI's second job
  runs it: 260 passed, 1 expected failure, none skipped, at CNS `v4.0.0` (the pin) and at
  `v4.1.0`. The demo exits 0. The "260 passed" this line gave on 2026-11-15 is the with-CNS
  count, and the older "201 tests" figure was out of date. CI is set to run the tests and
  the demo on Python 3.10 to 3.13; its results were not read.

## Running it

```bash
pip install -e .               # or: pip install -e ".[reservoir]"

python3 examples/run_kernel_demo.py   # commit, rejection, replay
python3 -m pytest tests/ -q           # 211 passed, 2 skipped, 1 expected failure (EXECUTED 2026-11-18; 260 passed with the cns extra)
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
