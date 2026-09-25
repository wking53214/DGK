# DGK

**Distributed Governance Control Engine.**

A governance kernel for systems that have to be able to prove, afterwards, what
they did and why.

This repository is a reconstruction. The original was lost; it has been rebuilt
from the source conversation preserved in the account's Gemini archive. See
`PROVENANCE.md` for where it came from and `RECONSTRUCTION.md` for what was
repaired, restored, and changed.

## The idea

Most systems record what they decided. This one is built so the record cannot
quietly disagree with what actually happened.

Two commitments do the work. **State is derived, never stored** — current state
is a replay of the event stream, so the ledger is the only source of truth and a
state value that contradicts the events behind it is detectable rather than
invisible. And **every accepted operation is chained** — entries are linked by
SHA-256 and signed with HMAC, so editing history after the fact leaves evidence.

## A transaction

Five stages. Any of the first three can stop it, and nothing commits until all
three have passed.

| Stage | Module | What happens |
|---|---|---|
| 1 | `stability.py` | Telemetry is classified into an operational regime |
| 2 | `interceptors.py` | Perimeter rules accept or reject the request |
| 3 | `ledger.py` | The proposed transition is checked against invariants |
| 4 | `ledger.py` | The event is appended and state re-projected |
| 5 | `linguistics.py` | Text is checked for compliance, then normalized |

The outcome is then written to a write-ahead audit log (`audit.py`).

Three design choices worth stating, because they are what the kernel is for:

**Rejection fails closed and names one rule.** The interceptor registry stops at
the first failure, so a rejected request comes back with the single rule that
rejected it and its reason — not a list to sift through.

**Regime classification has hysteresis.** A system sitting exactly on a
threshold would otherwise flip between regimes on noise alone, and every flip
would be an event in the ledger. The chassis requires a sustained crossing.

**Nothing commits on a rejected path.** A rejected transaction leaves no ledger
entry and no audit record. Two tests exist solely to pin that.

## Running it

Standard library only. `numpy` is optional and powers `EchoStateReservoir`
alone; `pytest` is needed for the tests.

```bash
pip install -e .               # or: pip install -e ".[reservoir]"

python3 examples/run_kernel_demo.py   # commit, rejection, replay
python3 -m pytest tests/ -q           # 33 tests
```

```python
from dgk import GovernanceOrchestrationKernel

# log_path (or DGK_AUDIT_LOG) is required; the file is created owner-only (0600)
kernel = GovernanceOrchestrationKernel(log_path="audit.log")
result = kernel.process_transaction(
    partition_id="region-us-east",
    telemetry_map={"latency": 134.2, "abort_rate": 0.008,
                   "reentry_rate": 0.04, "load_depth": 280.0,
                   "determinism_index": 0.998},
    text_payload="We are utilizing holistic paradigms.",
)
# -> COMMITTED, with a block hash, a ledger sequence number,
#    and "We are using complete models."
```

## What the pieces are

- **`taxonomy.py`** — regimes, telemetry payloads, provenance, events, contexts
- **`serialization.py`** — canonical JSON, the base every hash and signature rests on
- **`audit.py`** — append-only write-ahead log, HMAC signing and verification
- **`ledger.py`** — partitioned hash-chained event store, reducers, invariant manifests, snapshots
- **`linguistics.py`** — compliance validation (identity leakage, sycophancy) and jargon normalization
- **`stability.py`** — Welford statistics, Shannon entropy, Lyapunov state energy, regime classification with hysteresis, echo state reservoir
- **`interceptors.py`** — perimeter rules and the registry that runs them
- **`kernel.py`** — the orchestrator that wires all of it into one transaction

## Known characteristics

Two behaviours are pinned by tests as *observed*, not endorsed:

- **Sycophancy scoring dilutes across sentences.** Markers are scored per
  segment, so five sycophantic sentences each score below threshold while one
  dense clause is flagged. A wholly sycophantic paragraph can pass.
- **Identical telemetry produces identical energy.** With no spread in the
  running statistics there is no measurable deviation, so the Lyapunov energy
  is zero and the regime rests at `NOMINAL`. Variation is what the classifier
  reacts to, not magnitude.

That one is documented rather than corrected, since changing it would be a
behaviour change rather than a bug fix. Two genuine defects in this area *were*
corrected — a regime ratchet that could never recover, and raw magnitudes being
used as z-scores — both described in `RECONSTRUCTION.md`.
