# Deployment Profiles (Phase 19)

Spec reference: §53. Three named profiles select the crypto/runtime posture and
the Phase-19 resource bounds. An **enterprise operator** selects a profile; an
agent never can. Profiles only *subtract* or *harden* — they never widen a
security decision. Implemented in `cvztte/config/profiles.py`; resolve with
`cvztte.config.get_profile("demo" | "secure-lab" | "enterprise-reference")`.

> **Not production-certified.** The reference build runs `secure-lab`.
> `enterprise-reference` is a *configuration skeleton* only — see below. See
> `docs/ENVIRONMENT.md` for the NIST-standardized vs FIPS-validated distinction.

## `demo`

Fast, hackathon-friendly settings, **clearly labelled as weaker** (§53, §37).

- `security_profile = demo` (weaker CKKS parameters; must be labelled).
- Resource bounds: `max_ciphertext_bytes = 32 MiB`, `max_inflight_proofs = 4`,
  `max_inflight_fhe = 2`.
- Single-host, software key custody. Suitable only for demos/tests.

## `secure-lab`

Security-appropriate parameters — the profile the reference build actually runs.

- `security_profile = secure-lab` (128-bit CKKS).
- Separate threshold key-authority **processes** (genuine N-of-N; see
  `docs/THRESHOLD_FHE.md`).
- Stronger isolation; `requires_separate_hosts = True`.
- Resource bounds: `max_ciphertext_bytes = 16 MiB`, `max_inflight_proofs = 8`,
  `max_inflight_fhe = 4`.

## `enterprise-reference`

A **configuration skeleton** enumerating the infrastructure a production
deployment would require. It inherits `secure-lab` crypto (the skeleton adds
infrastructure, never weaker crypto), sets `requires_mtls = True`,
`requires_separate_hosts = True`, and `key_custody = "hsm-kms-tee"`.

**`production_certified` is `False` and the profile's own constructor forbids
setting it `True` (§53).** The reference build does **not** itself provide this
infrastructure; `InfraRequirement.satisfied_by_reference_build` is `False` for
every item below. This is stated honestly rather than implied away.

| Component | Requirement |
|---|---|
| topology | separate services/hosts per plane |
| transport | mutual TLS between all services |
| key-custody | HSM / KMS / TEE for signing & MAC keys |
| state | highly-available Redis / state store |
| observability | SIEM / SOC integration |
| supply-chain | signed policy/model/circuit releases |
| supply-chain | SBOM + container image signing |
| time | secure/attested clock source |
| resilience | disaster recovery / backups |
| assurance | external cryptographic/security audit |

### Why never "production-certified"

Certification is an external assurance activity (independent cryptographic and
security audit, FIPS-validated modules, attested hardware) that this reference
build has not undergone and cannot self-declare. Calling it certified would be a
false security claim; the profile encodes that prohibition as an invariant.

## Resource bounds

Each profile carries a frozen `ResourceLimits`:

- `max_ciphertext_bytes` — FHE broker refuses larger ciphertexts with
  `FHE_CIPHERTEXT_TOO_LARGE` (memory-exhaustion guard; §60.31 #146).
- `max_inflight_proofs` / `max_inflight_fhe` — fed to `BoundedAdmission`
  (`cvztte/config/backpressure.py`) so the saturating prover/FHE stages shed load
  fail-closed rather than buffer unboundedly (§52). See `docs/PERFORMANCE.md`.
