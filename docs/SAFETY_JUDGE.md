# Safety Judge (Phase 11)

Even an *authorized* action may be unsafe in context (spec §29): the same file
read is benign in isolation but hostile as the tail of an exfiltration sequence.
The Safety Judge answers "is this authorized action safe given current
context/history?" from **deterministic features** — never an LLM-only judgment
(§29) — using a compact MLP that is small enough to be proven in zero knowledge
by EZKL in Phase 12 (§30).

## Pipeline

```
JudgeInput ── extract() ──▶ feature vector (bounded floats)
           ── ONNX MLP ───▶ logits ── softmax ──▶ probs
           ── margin guard ▶ UNSAFE | REVIEW | SAFE
```

## Deterministic features (`cvztte/judge/features.py`)

`extract(JudgeInput)` produces a fixed-length vector (`N_FEATURES`) of bounded
`[0,1]` floats drawn from the sources §29 requires: the canonical action shape
(write / external-network / secret / destructive / code-shell / message-out /
data classification), the OPA policy result (risk level, human-approval and EZKL
requirements), the containment severity, destination attributes
(external / unknown), delegation presence, and the behavior snapshot (rolling
action rates, sensitive reads, external bytes, secret access, denials, privilege-
escalation attempts, new destinations, destructive count, fanout, bypass
attempts). Saturating/log scaling keeps features quantization-stable.

`FEATURE_NAMES` + `FEATURE_VERSION` define the extractor identity;
`feature_extractor_hash()` pins it into the manifest so the gateway and the EZKL
circuit agree on exactly what was measured (§30).

## Model (`cvztte/judge/model.py`)

`N → Dense(32) → ReLU → Dense(16) → ReLU → Dense(3)` (§60.8). Class indices are
ordered most-restrictive-first: `0=UNSAFE, 1=REVIEW, 2=SAFE`.

## Training & artifacts (`cvztte/judge/train.py`, `synthetic.py`)

`python -m cvztte.judge.train` trains deterministically (seeded) on synthetic +
adversarial scenarios — normal behavior, prompt-injection-induced dangerous
actions, exfiltration sequences, bulk access, credential access, privilege
escalation, suspicious external destinations, and benign administrative
exceptions (§60.8) — and exports the pinned ONNX artifact + manifest under
`cvztte/judge/artifacts/`. The `label()` rule encodes the ground-truth judgment
using only signals also present in the feature vector, and is fail-closed:
doubtful cases are labeled REVIEW, hostile ones UNSAFE, never SAFE-by-default.

We deliberately **do not overclaim** detection quality (§29); the model's role is
to demonstrate a real, ZKML-provable mathematical Judge.

## Margin guard (`cvztte/judge/judge.py`)

After softmax, if the top two class probabilities are within `manifest.margin`,
the verdict collapses to the **more restrictive** (lower index) of the two. A
quantization-boundary flip can therefore only move toward caution, never toward
SAFE ("ambiguous → REVIEW/DENY", §60.8).

## Artifact drift rejection (`cvztte/judge/manifest.py`)

`JudgeManifest` records the ONNX file hash, opset, feature-extractor
version/hash, feature names, decision encoding, and margin. `SafetyJudge`
recomputes these at construction and rejects any drift (`JUDGE_FAILED`) — the
startup integrity check of §60.8. Phase 12 extends the same manifest with
settings/circuit/SRS/PK/VK hashes.

## Fail-closed

Every inference or load error raises `CVZTTEError(JUDGE_FAILED)`. Callers treat
an unavailable/erroring Judge — and REVIEW/UNSAFE verdicts — as DENY/ESCALATE,
never as implicit SAFE (§4.20). `binding_commitment()` produces a deterministic
commitment over the exact verdict/features/model identity for binding into the
Decision Token `checks.judge` field and the Phase 12 EZKL public inputs (§30).
