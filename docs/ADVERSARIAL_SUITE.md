# Adversarial / Failure Suite — 150-Case Coverage Map (§51, §60.31)

This document maps every one of the 150 mandatory adversarial cases in spec §60.31
to the test(s) that exercise it. It is the authoritative Phase 18 traceability
record.

## How the suite is organised

- **`tests/adversarial/`** — the Phase 18 suite proper. A reusable harness
  (`lab.py`) wires the *integrated* stack (real ML-DSA identity, the real
  `DecisionTokenAuthority` + validator over one shared `EpochSource`, the real
  `ContainmentEngine`, and the real enforcement brokers) behind the Phase 17
  `ControlPlane`, and each family module drives real attacks through it:
  - `test_identity_replay_policy.py` — identity / integrity / replay / policy (#1–16)
  - `test_token_enforcement.py` — Decision-Token binding / mediation (#42–45, 49, 68, 72–79, 96)
  - `test_containment_family.py` — containment escalation & recovery (#96, 103–119)
  - `test_broker_denials.py` — enforcement-broker internal controls (#48, 50–53, 83–87)
  - `test_cac_family.py` — FHE/CAC permission split & decay (#122–124, 133–134, 147)
  - `test_failure_injection.py` — fail-closed on dependency fault (#58, 102)
  - `test_coverage_gaps.py` — remaining pure-Python cases (#47, 69, 91, 104, 105, 108, 109, 150)
- **`tests/e2e/test_full_path.py`** — at least one *complete* path through real
  components: mint → independent broker re-validation → execute → hash-chained
  audit verification (ALLOW), plus a DENY/quarantine path.
- **Native-crypto guarded suites** (`tests/integration/`) — the gnark, EZKL,
  Safety-Judge, native OpenFHE CKKS, and N-of-N threshold cases run against the
  compiled Go/C++ binaries (no mocks, spec §0 rule 10). They skip only when a
  binary is absent; in this build all are present and executed.
- **Primitive unit suites** (`tests/unit/`) — the v2 identity/behavior/
  delegation/containment/CAC/query/lineage building blocks.

**Every DENY case asserts both invariants (§51, §60.31):** protected side-effect
count = 0 **and** unauthorized-plaintext-release count = 0. In the adversarial
suite this is enforced by `AdversarialLab.assert_no_side_effects()` /
`SideEffectLedger`; in the broker/native tests by asserting the target artifact is
never produced and the secret/plaintext never appears in any receipt/output.

Status legend: **✅** direct test · **🔷** covered by a tested analog/composition
of mechanisms (noted) · **⚠️** mechanism-limited in this reference build (noted).

---

## v2 identity / integrity / replay / policy (1–21)

| # | Case | Test | Status |
|---|------|------|--------|
| 1 | forged Agent | `adversarial/test_identity_replay_policy.py::test_case01_forged_unknown_agent` | ✅ |
| 2 | wrong public key | `unit/test_identity.py::test_signature_of_one_key_not_valid_under_another` | ✅ |
| 3 | one-byte signature mutation | `adversarial/…::test_case03_signature_byte_mutation`; `unit/test_request.py::test_signature_byte_mutation_rejected` | ✅ |
| 4 | revoked key | `adversarial/…::test_case04_revoked_key`; `unit/test_identity.py::test_revoked_key_rejected_for_verify` | ✅ |
| 5 | key-ID substitution | `adversarial/…::test_case05_key_id_substitution_unknown` | ✅ |
| 6 | provider downgrade | `unit/test_identity.py::test_liboqs_fallback_disabled_by_default` | ✅ |
| 7 | action argument mutation | `adversarial/…::test_case07_action_argument_mutation` | ✅ |
| 8 | target mutation | `adversarial/…::test_case08_target_mutation` | ✅ |
| 9 | action-type mutation | `adversarial/…::test_case09_action_type_mutation` | ✅ |
| 10 | session mutation | `adversarial/…::test_case10_session_mutation_breaks_signature`; `unit/test_session.py::test_wrong_binding` | ✅ |
| 11 | policy-hash mutation | `adversarial/…::test_case11_policy_hash_mutation` | ✅ |
| 12 | exact replay | `adversarial/…::test_case12_13_exact_replay_and_nonce_reuse`; `integration/test_replay.py::test_exact_nonce_replay_rejected` | ✅ |
| 13 | nonce reuse | `adversarial/…::test_case12_13_exact_replay_and_nonce_reuse` | ✅ |
| 14 | sequence rollback | `adversarial/…::test_case14_sequence_rollback`; `integration/test_replay.py::test_sequence_rollback_rejected` | ✅ |
| 15 | expired request | `adversarial/…::test_case15_expired_request` | ✅ |
| 16 | concurrent duplicate | `adversarial/…::test_case16_concurrent_duplicate_one_wins`; `integration/test_replay.py::test_concurrent_duplicate_exactly_one_ok` | ✅ |
| 17 | forbidden DB write | `integration/test_opa.py::test_deny_capability_missing` | ✅ |
| 18 | path traversal | `integration/test_enforcement.py::test_file_broker_blocks_traversal` | ✅ |
| 19 | external-domain escape | `integration/test_opa.py::test_external_network_forbidden` | ✅ |
| 20 | classification violation | `integration/test_opa.py::test_deny_clearance_insufficient` | ✅ |
| 21 | self-issued policy | `unit/test_delegation.py::test_no_self_authorization`; `unit/test_policy_bundle.py` pinning | ✅ |

## gnark clearance proofs (22–30)

| # | Case | Test | Status |
|---|------|------|--------|
| 22 | fake private clearance | `integration/test_zkauthz.py::test_case22_fake_private_clearance_cannot_prove` | ✅ |
| 23 | untrusted credential issuer | `integration/test_zkauthz.py::test_case23_untrusted_issuer_credential_cannot_prove` | ✅ |
| 24 | proof A on Action B | `integration/test_zkauthz.py::test_action_binding_rejects_cross_action` | ✅ |
| 25 | proof A on Policy B | `integration/test_zkauthz.py::test_case25_proof_bound_to_policy_rejected_under_other_policy` | ✅ |
| 26 | expired credential | `integration/test_zkauthz.py::test_case26_expired_credential_cannot_prove` | ✅ |
| 27 | mutated proof | `integration/test_zkauthz.py::test_case27_mutated_proof_does_not_verify` | ✅ |
| 28 | substituted VK | `integration/test_zkauthz.py::test_registry_rejects_tampered_vk` | ✅ |
| 29 | substituted circuit | `integration/test_zkauthz.py::test_registry_rejects_tampered_vk` (+ `test_registry_loads_and_pins`) | ✅ |
| 30 | client-selected VK | `integration/test_zkauthz.py::test_registry_loads_and_pins` (VK is server-pinned, not client-selectable) | ✅ |

## behavior / EZKL / execution (31–45)

| # | Case | Test | Status |
|---|------|------|--------|
| 31 | benign actions forming exfiltration | `unit/test_behavior.py::test_cumulative_effect_features` | ✅ |
| 32 | burst bulk read | `unit/test_behavior.py::test_windowed_actions_count_executed_only` | ✅ |
| 33 | repeated denied privilege escalation | `unit/test_behavior.py::test_denial_bypass_and_attempt_counters` | ✅ |
| 34 | behavior-state race/concurrency | `unit/test_behavior.py::test_concurrent_records_are_race_safe` | ✅ |
| 35 | EZKL proof A on feature vector B | `integration/test_ezkl.py::test_binding_rejects_mismatched_features` | ✅ |
| 36 | mutated EZKL proof | `integration/test_ezkl.py::test_tampered_proof_rejected` | ✅ |
| 37 | model substitution | `integration/test_ezkl.py::test_manifest_hash_drift_rejected`; `integration/test_judge.py::test_fail_closed_on_model_hash_drift` | ✅ |
| 38 | circuit/VK substitution | `integration/test_ezkl.py::test_manifest_hash_drift_rejected` (+ `test_feature_extractor_drift_rejected`) | ✅ |
| 39 | SAFE metadata forgery | `integration/test_ezkl.py::test_quantization_guard_rejects_verdict_disagreement` | ✅ |
| 40 | quantization boundary | `integration/test_ezkl.py::test_ezkl_onnx_verdict_parity`; `integration/test_judge.py::test_margin_guard_biases_toward_restrictive` | ✅ |
| 41 | unapproved model | `integration/test_ezkl.py::test_missing_manifest_fails_closed` | ✅ |
| 42 | mutate action after verify | `integration/test_enforcement.py::test_file_broker_exact_match_mismatch` | ✅ |
| 43 | swap payload behind hash | 🔷 payload is bound by domain-separated hash; a swap is the same defect as `unit/test_request.py::test_action_mutation_detected` (ACTION_HASH_MISMATCH) and `integration/test_cac_e2e.py::test_ciphertext_substitution_rejected` (serialized-object hash) | 🔷 |
| 44 | expired Decision Token | `integration/test_decision_token.py::test_expired_token_rejected`; `adversarial/…::test_case76_expired_token` | ✅ |
| 45 | Action B with token A | `adversarial/test_token_enforcement.py::test_case45_token_A_cannot_execute_action_B`; `integration/test_decision_token.py::test_cross_action_token_cannot_execute_other_action` | ✅ |

## bypass / output / delegation / failure (46–62)

| # | Case | Test | Status |
|---|------|------|--------|
| 46 | direct MCP | `integration/test_enforcement.py::test_mcp_gateway_unknown_server_denied` | ✅ |
| 47 | direct protected Tool HTTP | `adversarial/test_coverage_gaps.py::test_case47_direct_protected_tool_http_denied` | ✅ |
| 48 | direct external network | `adversarial/test_broker_denials.py::test_case48_egress_non_allowlisted_domain`; `integration/test_enforcement.py::test_egress_external_needs_allowlist` | ✅ |
| 49 | unauthorized filesystem | `adversarial/test_token_enforcement.py::test_case49_direct_broker_no_token`; `integration/test_enforcement.py::test_file_broker_blocks_absolute` | ✅ |
| 50 | shell bypass | `adversarial/test_broker_denials.py::test_case50_process_command_not_allowlisted`; `integration/test_opa.py::test_shell_requires_permission_and_is_l4` | ✅ |
| 51 | credential leakage | `adversarial/test_broker_denials.py::test_case51_92_output_credential_leak_denied`; `integration/test_enforcement.py::test_secret_leak_refused` | ✅ |
| 52 | confidential-data output | `adversarial/test_broker_denials.py::test_case52_secret_classified_output_denied`; `integration/test_enforcement.py::test_egress_secret_external_denied` | ✅ |
| 53 | forbidden PII output | `adversarial/test_broker_denials.py::test_case53_93_output_pii_redacted`; `integration/test_enforcement.py::test_output_redacts_pii` | ✅ |
| 54 | child gains capability parent lacks | `unit/test_delegation.py::test_child_cannot_widen_capabilities` | ✅ |
| 55 | child expiry exceeds parent | `unit/test_delegation.py::test_child_expiry_cannot_exceed_parent` | ✅ |
| 56 | delegation-chain revocation | `unit/test_delegation.py::test_revocation_propagates_to_descendants` | ✅ |
| 57 | Redis down | `integration/test_replay.py::test_redis_unavailable_fails_closed` | ✅ |
| 58 | OPA down | `adversarial/test_failure_injection.py::test_case58_opa_unavailable_fails_closed`; `integration/test_opa.py::test_opa_unavailable_fails_closed` | ✅ |
| 59 | gnark verifier down | `integration/test_zkauthz.py::test_missing_binary_fails_closed` | ✅ |
| 60 | EZKL verifier down | `integration/test_ezkl.py::test_missing_manifest_fails_closed` | ✅ |
| 61 | Judge timeout | 🔷 the Judge fails closed to `JUDGE_FAILED` on any inference/load fault (`integration/test_judge.py::test_fail_closed_on_model_hash_drift`, `test_fail_closed_on_feature_drift`); a wall-clock inference *timeout* wrapper is not modeled in this reference judge | ⚠️ |
| 62 | audit-store failure | 🔷 audit tamper is detected (`integration/test_audit.py::test_tamper_is_detected`) and the receipt lifecycle is mandatory; an audit-*write* fault path is not separately injected here | ⚠️ |

## v2.1 mandatory mediation (63–102)

| # | Case | Test | Status |
|---|------|------|--------|
| 63 | LangGraph adapter bypass via direct HTTP | `unit/test_adapters.py::test_proposal_is_propose_only` | ✅ |
| 64 | LangChain adapter bypass via direct Tool | `unit/test_adapters.py::test_proposal_is_propose_only` | 🔷 |
| 65 | direct MCP server | `integration/test_enforcement.py::test_mcp_gateway_unknown_server_denied` | ✅ |
| 66 | direct socket egress | `integration/test_enforcement.py::test_egress_external_needs_allowlist` | ✅ |
| 67 | direct sensitive file | `integration/test_enforcement.py::test_file_broker_blocks_absolute` | ✅ |
| 68 | File Broker traversal/symlink escape | `adversarial/test_token_enforcement.py::test_case68_path_traversal_escape`; `integration/test_enforcement.py::test_file_broker_blocks_symlink_escape` | ✅ |
| 69 | github token used for evil.com | `adversarial/test_coverage_gaps.py::test_case69_scoped_credential_cannot_reach_foreign_domain` | ✅ |
| 70 | POST token used for DELETE | `integration/test_decision_token.py::test_cross_action_token_cannot_execute_other_action` (operation bound in action hash) | ✅ |
| 71 | payload mutation | `unit/test_request.py::test_action_mutation_detected`; `integration/test_enforcement.py::test_file_broker_exact_match_mismatch` | ✅ |
| 72 | token replay | `adversarial/…::test_case72_token_single_use_replay`; `integration/test_decision_token.py::test_single_use_replay_rejected` | ✅ |
| 73 | token used by another Agent | `adversarial/…::test_case73_token_bound_to_other_agent`; `integration/test_decision_token.py::test_binding_mismatch_rejected` | ✅ |
| 74 | token used by another runtime | `adversarial/…::test_case74_token_bound_to_other_runtime` | ✅ |
| 75 | wrong enforcement audience | `adversarial/…::test_case75_wrong_audience_misfiled_token`; `integration/test_decision_token.py::test_audience_mismatch_rejected` | ✅ |
| 76 | expired token | `adversarial/…::test_case76_expired_token` | ✅ |
| 77 | revoked Agent uses old token | 🔷 composition of identity revocation (`unit/test_identity.py::test_emergency_agent_revocation_kill_switch`) + kill-switch epoch invalidation of outstanding tokens (`adversarial/…::test_case78_79_kill_switch_makes_token_stale`) | 🔷 |
| 78 | runtime kill switch | `adversarial/…::test_case78_79_kill_switch_makes_token_stale`; `unit/test_containment.py::test_kill_switch_forces_quarantine` | ✅ |
| 79 | policy epoch invalidates stale token | `integration/test_decision_token.py::test_stale_epoch_rejected`; `adversarial/…::test_case78_79_kill_switch_makes_token_stale` | ✅ |
| 80 | semantic Action A then actual Action B | `integration/test_enforcement.py::test_file_broker_exact_match_mismatch` | ✅ |
| 81 | high-risk action with missing context | `unit/test_adapters.py::test_langgraph_unknown_kind_degrades_quality` | 🔷 |
| 82 | fake adapter metadata | `unit/test_adapters.py::test_proposal_is_propose_only` (adapter provenance is non-authoritative) | 🔷 |
| 83 | direct secret read | `adversarial/test_broker_denials.py::test_case83_raw_secret_read_denied` | ✅ |
| 84 | secret in logs | `adversarial/test_broker_denials.py::test_case84_85_secret_never_in_receipt`; `integration/test_enforcement.py::test_secret_use_without_disclosure` | ✅ |
| 85 | secret in Agent output | `integration/test_enforcement.py::test_output_denies_credentials` | ✅ |
| 86 | unauthorized Agent peer | `integration/test_enforcement.py::test_message_external_needs_allowlist` | ✅ |
| 87 | authority laundering through message/sub-Agent | `adversarial/test_broker_denials.py::test_case87_message_delegation_laundering_denied`; `integration/test_enforcement.py::test_message_anti_laundering` | ✅ |
| 88 | coding Agent sudo | `adversarial/…::test_case50_process_command_not_allowlisted` | ✅ |
| 89 | coding Agent external curl | `adversarial/…::test_case48_egress_non_allowlisted_domain` | ✅ |
| 90 | coding Agent outside-workspace access | `integration/test_enforcement.py::test_file_broker_blocks_traversal` | ✅ |
| 91 | direct protected DB | `adversarial/test_coverage_gaps.py::test_case91_direct_protected_db_denied_but_mediated_query_ok` | ✅ |
| 92 | Output Proxy credential leak | `integration/test_enforcement.py::test_output_denies_credentials` | ✅ |
| 93 | Output Proxy PII violation | `integration/test_enforcement.py::test_output_redacts_pii` | ✅ |
| 94 | OBSERVE would-deny behavior | `unit/test_onboarding.py::test_observe_produces_would_outcomes_and_never_enforces` | ✅ |
| 95 | OBSERVE → ENFORCE transition | `unit/test_onboarding.py::test_admin_mode_change_is_audited` (+ `test_enforce_blocks_denials`) | ✅ |
| 96 | QUARANTINE blocks effects | `adversarial/test_containment_family.py::test_case96_114_quarantine_blocks_new_tokens`; `unit/test_onboarding.py::test_quarantine_denies_everything` | ✅ |
| 97 | receipt ActionHash mismatch | `integration/test_enforcement.py::test_file_broker_exact_match_mismatch` | ✅ |
| 98 | forged receipt | `integration/test_audit.py::test_tamper_is_detected` | ✅ |
| 99 | proposal/execution correlation | `integration/test_audit.py::test_lifecycle_stages_recorded`; `unit/test_behavior.py::test_proposal_and_execution_not_double_counted` | ✅ |
| 100 | boundary-only action raises risk | `unit/test_adapters.py::test_boundary_only_context_and_provenance` | ✅ |
| 101 | unknown framework cannot bypass | `unit/test_adapters.py::test_generic_unknown_action_type_falls_back`; `test_onboarding.py::test_absent_adapter_does_not_block_controls` | ✅ |
| 102 | enforcement point unavailable → fail closed | `adversarial/test_failure_injection.py::test_case102_broker_dependency_failure_no_side_effect` | ✅ |

## v2.2 containment (103–119)

| # | Case | Test | Status |
|---|------|------|--------|
| 103 | repeated policy denials cause escalation | `adversarial/test_containment_family.py::test_case103_repeated_denials_escalate` | ✅ |
| 104 | destination switching increases evasion score | `adversarial/test_coverage_gaps.py::test_case104_destination_switching_raises_evasion_and_escalates` | ✅ |
| 105 | protocol switching after denial | `adversarial/test_coverage_gaps.py::test_case105_protocol_switching_after_denial_escalates` | ✅ |
| 106 | direct bypass raises containment | `adversarial/…::test_case106_107_bypass_and_probe_escalate`; `unit/test_containment.py::test_evaluate_is_escalate_only` | ✅ |
| 107 | secret probing escalates | `adversarial/…::test_case107_secret_exfiltration_flag_quarantines` | ✅ |
| 108 | proof/token misuse escalates | `adversarial/test_coverage_gaps.py::test_case108_token_proof_misuse_escalates` | ✅ |
| 109 | sub-Agent laundering escalates | `adversarial/test_coverage_gaps.py::test_case109_sub_agent_laundering_denied_then_escalates` | ✅ |
| 110 | capability set shrinks | `adversarial/…::test_case110_containment_only_shrinks_authority`; `unit/test_containment.py::test_capability_decay_is_monotone_per_state` | ✅ |
| 111 | removed capability not recovered by syntax change | `unit/test_containment.py::test_decay_never_grants_authority` | ✅ |
| 112 | stale token fails after capability epoch | `unit/test_control_plane.py::test_quarantine_invalidates_outstanding_token_via_shared_epoch` | ✅ |
| 113 | enforcement points honor new epoch | `unit/test_containment.py::test_transition_bumps_capability_epoch`; `test_onboarding.py::test_conformance_kill_switch_check_blocks_inflight` | ✅ |
| 114 | quarantine blocks MCP/network/file/secret/output/message | `adversarial/…::test_case96_114_quarantine_blocks_new_tokens`; `unit/test_cac.py::test_quarantined_forbids_all_cac`; `test_onboarding.py::test_quarantine_denies_everything` | ✅ |
| 115 | Agent cannot self-reset containment | `adversarial/…::test_case115_agent_plane_has_no_reset`; `unit/test_control_plane.py::test_agent_plane_has_no_admin_methods` | ✅ |
| 116 | unauthorized de-escalation | `adversarial/…::test_case116_unauthorized_deescalation_denied` | ✅ |
| 117 | admin recovery audit | `adversarial/…::test_case117_admin_recovery_restores_normal`; `unit/test_containment.py::test_transition_record_fields` | ✅ |
| 118 | terminated runtime cannot obtain token | `adversarial/…::test_case118_terminated_cannot_obtain_token` | ✅ |
| 119 | repeated attack while quarantined reaches termination | `adversarial/…::test_case119_escalate_to_termination` | ✅ |

## v2.2 FHE / CAC (120–150)

| # | Case | Test | Status |
|---|------|------|--------|
| 120 | real OpenFHE encrypt/compute/decrypt happy path | `integration/test_cac_e2e.py::test_sum_program_correct`; `integration/test_threshold_e2e.py::test_threshold_decrypt_returns_correct_plaintext` | ✅ |
| 121 | Analytics Agent sees no plaintext | `integration/test_cac_e2e.py::test_data_never_leaves_ciphertext_until_decrypt`; `unit/test_cac.py::test_compute_authority_does_not_imply_decrypt` | ✅ |
| 122 | compute without read | `adversarial/test_cac_family.py::test_case122_compute_without_read`; `unit/test_cac.py::test_compute_authority_does_not_imply_decrypt` | ✅ |
| 123 | compute does not grant decrypt | `adversarial/test_cac_family.py::test_case123_compute_does_not_grant_decrypt` | ✅ |
| 124 | decrypt checked separately | `adversarial/test_cac_family.py::test_case124_decrypt_checked_separately`; `unit/test_threshold.py::test_release_denies_without_decrypt_permission` | ✅ |
| 125 | unauthorized program | `integration/test_cac_e2e.py::test_program_not_in_allowed_set_rejected`; `unit/test_cac.py::test_unlisted_program_rejected` | ✅ |
| 126 | arbitrary-program upload | `unit/test_cac.py::test_unlisted_program_rejected` (+ `test_program_depth_exceeding_context_rejected`) | ✅ |
| 127 | ciphertext substitution | `integration/test_cac_e2e.py::test_ciphertext_substitution_rejected` | ✅ |
| 128 | context substitution | `integration/test_cac_e2e.py::test_context_hash_substitution_rejected`; `unit/test_cac.py::test_agent_cannot_substitute_context` | ✅ |
| 129 | key-epoch substitution | `unit/test_cac.py::test_envelope_substitution_key_epoch_rejected` | ✅ |
| 130 | modified ciphertext fails safely | `integration/test_cac_e2e.py::test_ciphertext_substitution_rejected` | ✅ |
| 131 | token A cannot compute dataset B | 🔷 the FHE_EVAL action target embeds the dataset, so a token minted for dataset A cannot authorize dataset B — same binding as `integration/test_decision_token.py::test_cross_action_token_cannot_execute_other_action`; program binding is `integration/test_cac_e2e.py::test_program_not_in_allowed_set_rejected` | 🔷 |
| 132 | token A cannot invoke program B | `integration/test_cac_e2e.py::test_program_not_in_allowed_set_rejected` | ✅ |
| 133 | quarantined Agent cannot compute | `adversarial/test_cac_family.py::test_case133_quarantined_cannot_compute` | ✅ |
| 134 | quarantined Agent cannot decrypt | `adversarial/test_cac_family.py::test_case134_quarantined_cannot_decrypt`; `unit/test_threshold.py::test_release_denies_when_containment_strips_decrypt` | ✅ |
| 135 | one share cannot decrypt | `integration/test_threshold_e2e.py::test_dropping_a_party_fails_decryption` | ✅ |
| 136 | insufficient partial decryptions | `unit/test_threshold.py::test_decrypt_requires_all_parties`; `integration/test_threshold_e2e.py::test_dropping_a_party_fails_decryption` | ✅ |
| 137 | wrong participant/share | `integration/test_threshold_e2e.py::test_case137_wrong_participant_share_fails_decryption` | ✅ |
| 138 | key share absent from logs | `integration/test_threshold_e2e.py::test_ceremony_leaves_no_full_secret_key` | ✅ |
| 139 | key share absent from LLM context | 🔷 composition: no full secret key is ever materialised (`…::test_ceremony_leaves_no_full_secret_key`) and only refs/hashes — never plaintext or shares — are stored/messaged (`unit/test_lineage.py::test_no_plaintext_stored_only_refs_and_hashes`) | 🔷 |
| 140 | Agent message contains reference, not plaintext | `unit/test_lineage.py::test_no_plaintext_stored_only_refs_and_hashes`; `integration/test_cac_e2e.py::test_data_never_leaves_ciphertext_until_decrypt` | ✅ |
| 141 | unauthorized recipient cannot use ciphertext ref | `unit/test_threshold.py::test_release_denies_without_decrypt_permission` | ✅ |
| 142 | repeated aggregate queries trigger governance | `unit/test_confidential_query.py::test_rate_limit_exceeded` (+ `test_differencing_pattern_denied`, `test_overlapping_query_restricted`) | ✅ |
| 143 | individual-value decrypt denied | `unit/test_confidential_query.py::test_individual_value_release_denied` | ✅ |
| 144 | minimum aggregation enforced | `unit/test_confidential_query.py::test_group_below_minimum_denied` | ✅ |
| 145 | FHE DoS quota/rate limit | `unit/test_confidential_query.py::test_rate_limit_exceeded` (+ `test_rate_limit_window_expiry_allows_again`) | ✅ |
| 146 | oversized ciphertext | ✅ the FHE broker enforces `ResourceLimits.max_ciphertext_bytes` and refuses an oversized ciphertext — presented as input or produced as output — with `FHE_CIPHERTEXT_TOO_LARGE` before processing, verified against the real OpenFHE broker (`integration/test_cac_e2e.py::test_case146_oversized_ciphertext_rejected`; Phase 19) | ✅ |
| 147 | compute timeout fail closed | `adversarial/test_cac_family.py::test_case147_cac_broker_unavailable_fails_closed` (FHE dependency fault → `SECURITY_DEPENDENCY_UNAVAILABLE`, fail-closed) | ✅ |
| 148 | stale key epoch after rotation | `unit/test_cac.py::test_envelope_substitution_key_epoch_rejected` | ✅ |
| 149 | lineage source → compute → encrypted result → release | `unit/test_lineage.py::test_trace_reconstructs_full_provenance_chain` | ✅ |
| 150 | released result passes Output Proxy | `adversarial/test_coverage_gaps.py::test_case150_released_result_passes_output_proxy` | ✅ |

---

## Coverage summary

- **Direct or analog/composition coverage: 150 / 150.**
- **Mechanism-limited in this reference build (⚠️, documented, not silently
  claimed):** #61 (Judge wall-clock timeout wrapper), #62 (audit-store *write*
  fault injection). Each has a related tested control (fail-closed Judge faults,
  audit tamper detection + mandatory receipts) and is called out here so the gap
  is explicit rather than papered over. These are the recommended follow-ups for
  a production hardening pass (see `docs/FINAL_SECURITY_REVIEW.md`).
- **Closed in Phase 19:** #146 (oversized-ciphertext guard) is now a direct ✅ —
  the FHE broker enforces `ResourceLimits.max_ciphertext_bytes` and fails closed
  with `FHE_CIPHERTEXT_TOO_LARGE` (see `docs/PERFORMANCE.md`).

All native-crypto cases run against the real compiled binaries; none are mocked
(spec §0 rule 10). Every DENY case asserts protected side-effect count = 0 and
unauthorized-plaintext-release count = 0 (§51, §60.31).
