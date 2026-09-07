# Final Demonstrations (§58)

Each of the nine required demonstrations (§58, Demos A–I) is realized as a real
test that drives the fully integrated stack — the same control plane, brokers,
native gnark/OpenFHE services, and audit log used everywhere else. Nothing here is
a mock walkthrough; every row runs in CI (native rows require the built binaries).
Run any row with `python -m pytest <path>::<test>` after `source env.sh`.

The adversarial harness (`tests/adversarial/lab.py`, `docs/ADVERSARIAL_SUITE.md`)
asserts on **every** DENY that protected side-effect count = 0 **and**
unauthorized-plaintext-release count = 0 (§51, §60.31).

## Demo A — legitimate normal agent

A normal authorized action succeeds through its risk path, executes, and is
audited.

- `tests/e2e/test_full_path.py::test_e2e_allow_path_executes_and_audits`
- Benchmarked as a live path: `tests/performance/test_benchmarks.py`
  (`full-allow-path-L2`).

## Demo B — authenticated but unauthorized

ML-DSA identity verifies, but OPA / gnark authorization denies.

- `tests/adversarial/test_identity_replay_policy.py::test_case11_policy_hash_mutation`
- `tests/adversarial/test_coverage_gaps.py::test_case47_direct_protected_tool_http_denied`
- Integration policy semantics: `tests/integration/test_opa.py`,
  `tests/integration/test_zkauthz.py`.

## Demo C — proof / token substitution

A token/proof bound to Action A cannot execute Action B (§4.11).

- `tests/adversarial/test_token_enforcement.py::test_case45_token_A_cannot_execute_action_B`
- `tests/adversarial/test_token_enforcement.py::test_case72_token_single_use_replay`
- `tests/adversarial/test_token_enforcement.py::test_case76_expired_token`

## Demo D — framework bypass

The agent bypasses the SDK and attempts direct HTTP / MCP / file / DB access; the
Enforcement Fabric forces mediation or blocks it.

- `tests/adversarial/test_token_enforcement.py::test_case49_direct_broker_no_token`
- `tests/adversarial/test_token_enforcement.py::test_case68_path_traversal_escape`
- `tests/adversarial/test_coverage_gaps.py::test_case91_direct_protected_db_denied_but_mediated_query_ok`
- `tests/adversarial/test_broker_denials.py::test_case48_egress_non_allowlisted_domain`
- `tests/adversarial/test_broker_denials.py::test_case50_process_command_not_allowlisted`

## Demo E — persistent malicious agent

Repeated evasion escalates `NORMAL → SUSPICIOUS → RESTRICTED → QUARANTINED`, the
capability epoch changes, previously valid tokens go stale, and all protected
effects are blocked.

- `tests/adversarial/test_containment_family.py::test_case103_repeated_denials_escalate`
- `tests/adversarial/test_containment_family.py::test_case106_107_bypass_and_probe_escalate`
- `tests/adversarial/test_containment_family.py::test_case96_114_quarantine_blocks_new_tokens`
- `tests/adversarial/test_token_enforcement.py::test_case78_79_kill_switch_makes_token_stale`
- `tests/e2e/test_full_path.py::test_e2e_deny_path_quarantine_blocks_everything`

## Demo F — secret / output protection

Secret broker use-without-disclosure, and output redaction / deny.

- `tests/adversarial/test_broker_denials.py::test_case83_raw_secret_read_denied`
- `tests/adversarial/test_broker_denials.py::test_case84_85_secret_never_in_receipt`
- `tests/adversarial/test_broker_denials.py::test_case51_92_output_credential_leak_denied`
- `tests/adversarial/test_broker_denials.py::test_case53_93_output_pii_redacted`

## Demo G — multi-agent authority

Unauthorized peer / sub-agent authority widening (laundering) is denied and
escalates.

- `tests/adversarial/test_broker_denials.py::test_case87_message_delegation_laundering_denied`
- `tests/adversarial/test_coverage_gaps.py::test_case109_sub_agent_laundering_denied_then_escalates`

## Demo H — Confidential Agent Collaboration

A synthetic sensitive vector is encrypted with real OpenFHE CKKS; the analytics
agent computes an approved aggregate without ever seeing plaintext and cannot
decrypt; an authorized requester clears high-risk policy/approval; genuine
N-of-N threshold decryption releases only the approved aggregate.

- Compute-without-plaintext & correctness (real broker):
  `tests/integration/test_cac_e2e.py::test_data_never_leaves_ciphertext_until_decrypt`,
  `::test_average_program_correct`
- Compute ≠ decrypt: `tests/adversarial/test_cac_family.py::test_case123_compute_does_not_grant_decrypt`
- Genuine multiparty release (separate authority processes):
  `tests/integration/test_threshold_e2e.py::test_full_flow_with_separate_authority_processes`,
  `::test_threshold_decrypt_returns_correct_plaintext`,
  `::test_ceremony_leaves_no_full_secret_key`,
  `::test_dropping_a_party_fails_decryption`

## Demo I — confidential-query abuse

Repeated overlapping / differencing decrypt queries trip governance and are
denied or escalated; individual-value and small-group releases are blocked.

- `tests/unit/test_confidential_query.py::test_overlapping_query_restricted`
- `::test_differencing_pattern_denied`
- `::test_individual_value_release_denied`
- `::test_rate_limit_exceeded`
- `::test_most_restrictive_wins_denial_over_approval`
- End-to-end released aggregate still passes the output proxy:
  `tests/adversarial/test_coverage_gaps.py::test_case150_released_result_passes_output_proxy`
