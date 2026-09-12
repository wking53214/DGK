# Provenance

## Origin

DGK was built in a Google Gemini notebook named
`DGK (Distributed Governance Kernel)`.

The engine in this repository comes from a single activity record timestamped
`2026-06-22T03:34` — a 765-line Python module self-titled **"GOV4 Distributed
Governance Control Engine, v4.0.0"**, pasted into the conversation with the
question "would it be of benefit to merge this Kernel as well?"

**Recovered from:** `Gemini_History/Takeout/My Activity/Gemini Apps/myactivity.json`
(record index 886), and the identical copy in
`Gemini_Extraction/source/raw/original_gemini_export.json`.

## The conversation it came from

That record sits in the middle of a fast merging session on 22 June 2026, in
which several governance kernels were pasted in one after another and combined:

| Record | What was pasted |
|---|---|
| `894` | GSA-DIT — Deterministic Integrity Tower |
| `895` | GSA Core Framework v8.5 |
| `884` | GovernanceSystemsArchitectureMasterKernel |
| `886` | **GOV4 Distributed Governance Control Engine — this repository** |
| `876` | VANGUARD — Validation Matrix & Neutral Governance Automated Routing |
| `874` | SRE — System Resilience Evaluator |

The session's own answer to "go ahead and bring them together" proposed a
**Master/Vassal** topology it called the Unified Sovereign Governance Kernel:
VANGUARD and SRE at the perimeter, GSA-Master as orchestrator, and
DIT + GOV4 + DGK as the execution core.

That composite was never realized as working code. Its sketches reference
classes defined only in the separately pasted kernels and were never re-emitted
as a runnable whole, which matches an August 2026 assessment of the original
repository: of fourteen archived artifacts, one executed, and trivially.

**This repository is the GOV4 kernel alone** — the one component of that stack
that was substantially complete. The other named systems have their own
repositories under the same account; nothing from them is duplicated here.

## What is not from that record

A later record (`2026-07-04T20:25`) carries the DGK notebook tag but contains
the generic "GSA Universal Cryptographic Interlock Wrapper", the same template
applied across many unrelated codebases in that period. It contains no DGK
domain logic and contributed nothing to this package. The wrapper itself is
already reconstructed in the `SAGE-K` repository.

## A note on the ESN and Lyapunov machinery

The sibling `SAGE-K` reconstruction carries a docstring advertising "Echo State
Network reservoirs" and "Lyapunov Stability Engines", and its README records
that neither exists anywhere in that code.

They exist here. `stability.py` contains a real `EchoStateReservoir` with
recurrent and input weight matrices and a pseudo-inverse readout, and a real
`calculate_lyapunov_state_energy` building a weighted quadratic form over
z-scored telemetry. The naming in SAGE-K was not invented — it was inherited
from a sibling kernel that genuinely implemented it.

## Repository history

The original `wking53214/DGK` held the engine alongside flat artifact files
archived from the transcript, plus a JSON file. That repository no longer
exists: the GitHub repo of that name is empty, and its artifacts, provenance
notes and transcript are gone. This is a September 2026 reconstruction built
from the archive, not a recovery of those files.

## Status in the research corpus

DGK previously sat in the cross-tool Gemini arm of an architecture study, where
it was assessed as a borderline pass — one of fourteen artifacts executing, and
that one trivial. Following the data loss it has been removed from that study
set: a reconstruction cannot carry the evidentiary weight the original artifact
would have, and the corpus has sufficient primary systems without it. This
repository exists to be useful software, and is documented as such.
