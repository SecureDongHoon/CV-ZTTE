# Kill Switch

Spec references: §4.13/§4.15 (immediate authority revocation; audited),
§60.29 (admin plane separation). Code: `cvztte/containment/engine.py`
(`kill_switch`), `cvztte/control_plane/planes.py` (`AdminPlane`),
`cvztte/control_plane/http_api.py`. See also `docs/CONTAINMENT_ENGINE.md`,
`docs/DECISION_TOKEN.md`.

## What it does

`ContainmentEngine.kill_switch(*, subject, agent_id, target_state, reason_codes,
runtime_id=None, now=None)` (`engine.py:260`) forces a subject to a chosen
containment state — up to and including `TERMINATED`, which the automatic
`ThresholdPolicy.assess` deliberately never issues on its own (`policy.py:8-11`).
It commits through the same `_commit_transition` path as any escalation, so it:

1. Bumps the shared `capability_epoch` atomically (`engine.py:174-180, 210`),
   immediately invalidating every outstanding Decision Token for everyone —
   validation step 6 raises `DECISION_TOKEN_EPOCH_STALE`
   (`cvztte/decision/validator.py:157-161`).
2. Sets the subject's state so `blocks_new_consequential_tokens()` is True at
   QUARANTINED/TERMINATED (`model.py:119-121`), blocking new mints at both
   `ControlPlane.evaluate` and approve/mint time (`plane.py:230-235, 341-346`).
3. Writes an audited transition with reason codes.

The net effect is verified end to end in the conformance harness: after
`kill_switch(...)`, the live FileBroker rejects the previously-valid action and
nothing is written to disk (`cvztte/onboarding/conformance.py:210-229`).

## It is admin-only (plane separation, §60.29)

An agent literally holds no kill-switch method. The kill switch is reachable only
through the **admin plane**, which is a separate object capability from the agent
plane (Phase 17). `AdminPlane` methods call `self._authz.require(principal)`
against an allowlist authorizer before acting (`planes.py:153-162`), and the HTTP
route requires an admin principal header (`http_api.py:143-159`). There is no path
by which agent-plane input reaches `kill_switch` without passing the admin
authorizer. Mode changes and admin operations are audited.

## It only removes authority

Consistent with the containment invariant, the kill switch can only move a subject
to a *more* contained state and can never grant capability — it shares the
escalate-only, intersection-based machinery documented in
`docs/DYNAMIC_CAPABILITY_DECAY.md`. Reversing it requires the explicit,
method-gated, audited `recover()` flow (TERMINATED accepts only `REONBOARD`),
never a self-service action by the contained agent.
