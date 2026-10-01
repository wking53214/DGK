# Reconstruction record

The original `wking53214/DGK` is gone. This package was rebuilt in September
2026 from the source conversation preserved in the account's Gemini archive.

The rebuild **optimizes for working software**. DGK was removed from the
research study set after the data loss, so there is no reason to preserve
defects for fidelity's sake. Every change is listed below.

## Source and condition

One activity record: a 765-line module, 34 classes and 63 functions, pasted
into the June 22 merge session. It was in unusually good condition for a
recovered artifact — a static analysis found only **four undefined names** in
the whole file.

It did not run as recovered. Getting it to run took repairs in four categories.

### Repairs to the recovered text

**1. Indentation damage (4 lines).** The export flattened four consecutive
lines inside `LinguisticComplianceValidator._evaluate_pronoun_density` to nine
spaces instead of eight. Repaired by snapping to the enclosing block.

**2. A corrupted enum reference (1 line).** `REGIME_SEVERITY_INDEX` contained
`RESOURCE_SATURATED.RESOURCE_SATURATED: 3` — the `OperationalRegime.` prefix
had been overwritten by the member name. Raised `NameError` at import.

**3. Four lost classes, restored from their call sites.** `Interceptor`,
`InterceptorRegistry`, `RequestNormalizer` and `LanguageNormalizer` were
referenced by the kernel but their definitions did not survive. Each contract
is fully pinned by how the kernel uses it:

| Restored | Contract fixed by |
|---|---|
| `Interceptor` | `ContentFilterInterceptor` subclasses it; needs `name` and `enforce(context) -> RuleResult` |
| `InterceptorRegistry` | kernel calls `.register(...)` then `.evaluate(context)`, and reads `.passed` / `.details` |
| `RequestNormalizer` | kernel calls `RequestNormalizer.normalize(payload) -> GovernanceContext` |
| `LanguageNormalizer` | kernel calls `.normalize(text)` and stores it as `scrubbed_text` |

`LanguageNormalizer` required a judgement call, since only its signature was
recoverable and not its substitution table. It is built from the jargon the
recovered demo payload was written to exercise — *"utilizing holistic paradigms
to operationalize granular and suboptimal systems"* — plus the first-person
hedging the sibling DIT kernel's sanitizer targeted. The demo then validates
it: that sentence normalizes to *"We are using complete models to run detailed
and inadequate systems."* Every jargon term in the test payload is covered,
which is good evidence the table matches the original's intent, though not
proof it matches its contents.

**4. A broken optional-dependency guard.** The `try/except ImportError` around
`jwt`, `redis` and `fastapi` only handles a *missing* module. A module that is
present but broken raises something else and escapes the guard entirely, taking
the whole import down. Widened to catch any failure, since the point of the
guard is that these dependencies are optional.

## Defects fixed

### 1. The compliance validator raised on any real text

`LinguisticComplianceValidator.validate_text_stream` looked up
`runtime_thresholds["compliance_deviation_detected"]` — the **violation label**,
not a threshold key. The thresholds the constructor defines are
`identity_leakage_index` and `compliance_deviation_index`.

Any segment with non-zero clause weight reached that line and raised
`KeyError`. Stage 5 of every transaction was unreachable. Corrected to the key
that exists, and pinned by a regression test.

### 2. The regime classifier was a one-way ratchet

`HysteresisControlChassis` escalated freely but could never recover. Its
de-escalation branch required `self.current_regime == OperationalRegime.NOMINAL`
— but NOMINAL is severity 1, the minimum, so a *strictly lower* resolved
severity cannot exist when that test is true. The branch was unreachable.

A system that spiked once stayed in the worse regime for the life of the
process. Since the regime gates downstream behaviour and every change is a
ledger event, this is the most consequential defect in the file.

Replaced with actual hysteresis, which is what the class name and docstring
describe: escalate on the first bad reading, recover only after a configurable
run of consecutive calmer ones (default 3), with any re-spike resetting the
run. Four tests cover it.

### 3. Raw magnitudes were used as z-scores

`calculate_lyapunov_state_energy`'s inner `resolve_z_score` fell back to the raw
value when the standard deviation was below `1e-6`:

```python
return (value - mean) / std_dev if std_dev > 1e-6 else value
```

A metric with no established spread therefore entered the energy sum at full
magnitude and was then squared. `load_depth` of 280 contributed 280² — around
15,000 of a total energy of 15,362, swamping every other term and holding the
classifier in `ANOMALOUS_DRIFT` permanently once combined with defect 2.

A value with no measurable deviation from its own baseline should contribute
nothing, so the fallback now returns `0.0`.

### 4. Import-time side effects

The API gateway section instantiated `GovernanceOrchestrationKernel()` at module
scope, which opened a write-ahead log at `/tmp/gov4_central_ssot.log` merely on
import — before any caller had chosen a log path. That section is not part of
the package; the kernel is constructed by the caller, and the demo uses a
temporary directory. The kernel itself has no default path either: `log_path`
(or `DGK_AUDIT_LOG`) is required, and the log is created owner-only (0600) and
refuses to follow a symlink at that path.

## Structure

The flat module was split into eight modules along its own section banners, with
no logic moved between them: `taxonomy`, `serialization`, `audit`, `ledger`,
`linguistics`, `stability`, `interceptors`, `kernel`.

`numpy` was a hard top-level import but is used only by `EchoStateReservoir`. It
is now an optional extra (`pip install "dgk[reservoir]"`); the rest of the
kernel is standard library only.

## Known behaviour, left alone

Two characteristics are pinned by tests as observed rather than endorsed:

- **Sycophancy scoring dilutes across sentences.** Scoring is per-segment, so
  five sycophantic sentences each score 0.1 and none clears the 0.22 threshold,
  while one dense clause scoring 0.5 is flagged. A wholly sycophantic paragraph
  can pass. Changing it means scoring at document level — a behaviour change.
- **Identical telemetry yields zero energy.** With no spread there is no
  deviation, so the classifier rests at `NOMINAL`. It reacts to variation, not
  magnitude.

## Verification

- 43 tests pass, including regressions for all three logic defects and five
  that pin the audit log's location and permissions.
- The demo runs end to end: a transaction commits with a hash-chained ledger
  entry, a forbidden one is rejected with nothing written to the ledger or the
  audit log, and the log replays.
- CI runs the suite and the demo on Python 3.10 through 3.13.

## What is not here

- The original repository's flat artifact files, its JSON file, its provenance
  notes and its transcript. All lost; thirteen of fourteen artifacts did not
  execute in any case.
- The Unified Sovereign Governance Kernel composite. It was never realized as
  working code, and its constituent systems have their own repositories.
- Any FastAPI, Redis or JWT integration. The recovered gateway section was a
  handful of lines wrapping the kernel behind mock fallbacks; the kernel's own
  API is the supported surface.
