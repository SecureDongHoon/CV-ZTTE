# Threshold / Multiparty FHE

Spec references: §41, §42, §60.25, §60.26.

Phase 15 replaces the Phase 14 single-key custody with **genuine OpenFHE
multiparty decryption**. This document states the *actual* protocol semantics, as
§41 requires.

## Actual semantics: N-of-N, not t-of-n

The reference uses OpenFHE's interactive multiparty CKKS protocol
(`MultipartyKeyGen`, `MultipartyDecryptLead`/`Main`/`Fusion`,
`MultiEvalSumKeyGen`/`MultiAddEvalSumKeys`). In this protocol the joint secret is
the **sum** of every party's share, `s = s_a + s_b + s_c`. Decryption requires a
partial from **every** party.

**This is N-of-N: all configured participants are required.** We do **not** call
it "2-of-3" — the selected workflow does not support recovering the plaintext
from any proper subset of the parties. Dropping a single party makes decryption
fail cryptographically (the integration test
`test_dropping_a_party_fails_decryption` demonstrates this: a 2-of-3 fusion
produces a decode/approximation-error failure, mapped fail-closed to
`FHE_COMPUTE_FAILED`).

The `FHEContext.threshold` (`ThresholdConfig`) records this honestly:
`required_semantics = "all N participants required (N-of-N)"`.

## Reference authorities (§41, §60.25)

Three logical authorities, run as **separate processes** via `services/`:

| Party | Role | Service entrypoint |
|-------|------|--------------------|
| A | Data Owner Authority | `services/fhe-key-authority-a/main.py` |
| B | Security/Privacy Authority | `services/fhe-key-authority-b/main.py` |
| C | CV-ZTTE Decryption Authority | `services/fhe-key-authority-c/main.py` |

Each is a standalone process (`cvztte.cac.threshold.service.run_authority_cli`)
that owns exactly one secret-share directory and shells to the native broker.
The `DecryptCoordinator` (`services/decrypt-coordinator/main.py`) orchestrates
them but holds **no** share. In tests, `KeyAuthority` runs the same operations
in-process and `SubprocessParticipant` runs them as separate OS processes; both
are exercised end to end.

## No persisted full secret key (§41)

The key ceremony (`ThresholdKeyCeremony`) chains the parties:

```
A: KeyGen                    -> share s_a  (stays in A's dir)
B: MultipartyKeyGen(pub_A)   -> share s_b  (stays in B's dir), joint pub A+B
C: MultipartyKeyGen(pub_AB)  -> share s_c  (stays in C's dir), joint pub A+B+C
```

Only the **joint public key** and **joint eval-sum keys** are installed into the
shared context directory. It contains `context.bin`, `key-pub.bin`,
`eval-sum.bin` — and **never** a `key-sec.bin`
(`test_ceremony_leaves_no_full_secret_key` asserts exactly this file set). Each
`share-sec.bin` lives only in its party's own directory. No service ever
reconstructs or writes the combined secret key.

No multiparty eval-mult (relinearization) key is generated: the allowlisted
programs (`SUM_V1`, `AVERAGE_V1`, `WEIGHTED_SCORE_V1`) never multiply ciphertext
by ciphertext — `WEIGHTED_SCORE_V1` multiplies by a plaintext weight vector — so
only joint eval-sum keys are needed.

## Secret shares never enter LLM / log / audit (§41)

Shares exist only as `share-sec.bin` files opened by the broker inside a party's
own process. The broker prints only operation metadata (party tag, `installed`,
`partial`), never key bytes; the authority CLI and coordinator print JSON status
only. Failures emit a stable error code, never `detail` with key material.

## Decryption workflow and release policy (§42, §60.26)

Decryption is a **separate high-risk action** from computation. `DecryptCoordinator.decrypt`:

1. Enforces **N-of-N presence** — fewer than the configured parties →
   `FHE_THRESHOLD_INSUFFICIENT`.
2. Runs the **release gate** (`ThresholdReleasePolicy`) *before* any partial
   decryption:
   - requester holds `DECRYPT_RESULT` after containment decay (§42, §47) —
     compute authority never suffices; `RESTRICTED`+ strips it →
     `FHE_DECRYPT_DENIED`;
   - the result ciphertext bytes still match the authorized `ResultEnvelope`
     hash (no result substitution, §38) → else `FHE_RESULT_RELEASE_DENIED`;
   - human approval is present for `CONFIDENTIAL`/`SECRET` releases (§48) → else
     `APPROVAL_REQUIRED`.
3. Collects one partial decryption from **every** party (lead first) and fuses
   them via the broker.

### What is deferred (documented, not silently skipped)

- **Output Proxy / DLP** on the released plaintext is wired in Phase 17 (§60.26).
- **Confidential Query Governance** (decrypt-count / aggregation-size /
  differencing accounting, §45/§60.27) is Phase 16 and plugs in as an additional
  gate before release. This release gate is **not** differential privacy.

The release gate refuses to release unless its own checks pass; the deferred
layers only add further restriction, never relax it.
