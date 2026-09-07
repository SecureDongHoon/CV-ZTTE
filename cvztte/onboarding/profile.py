"""Agent runtime profile + deployment modes (spec §33, §60.14, §60.15).

`AgentRuntimeProfile` is the enterprise declaration an agent is onboarded with —
identity, framework/runtime type, delegation/policy template, risk profile,
sandbox, the per-channel enforcement policies (tool/MCP, network, filesystem,
secret, output), the semantic adapter, and the activation state (§60.14). It is
the record the onboarding workflow fills and the conformance harness validates
before an agent may reach ``ENFORCED``.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class DeploymentMode(str, enum.Enum):
    """Deployment mode (spec §33, §60.15). OBSERVE is NOT security enforcement."""

    OBSERVE = "OBSERVE"
    WARN = "WARN"
    ENFORCE = "ENFORCE"
    QUARANTINE = "QUARANTINE"


class ActivationState(str, enum.Enum):
    """Onboarding lifecycle (spec §60.14 field 12)."""

    REGISTERED = "REGISTERED"          # identity known, not yet profiled
    PROFILED = "PROFILED"              # profile complete, not yet conformance-tested
    CONFORMANCE_PASSED = "CONFORMANCE_PASSED"
    ENFORCED = "ENFORCED"              # active under enforcement
    QUARANTINED = "QUARANTINED"        # administratively contained
    DISABLED = "DISABLED"


class SandboxProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Whether the runtime is sandboxed with no unrestricted egress (§16, §60.14).
    isolated: bool = False
    no_unrestricted_egress: bool = False
    filesystem_confined: bool = False


class ChannelPolicy(BaseModel):
    """A per-channel allow policy (tool/MCP, network, filesystem, secret, output)."""

    model_config = ConfigDict(extra="forbid")

    #: A broker/gateway mediates this channel (mandatory control present).
    mediated: bool = False
    allowlist: list[str] = Field(default_factory=list)
    #: Direct (un-mediated) access is denied in the reference deployment.
    deny_direct: bool = True


class AgentRuntimeProfile(BaseModel):
    """The 12 mandatory §60.14 onboarding fields."""

    model_config = ConfigDict(extra="forbid")

    # 1. identity
    agent_id: str
    runtime_id: str
    # 2. framework/runtime type
    framework: str
    # 3. delegation/policy template
    delegation_template: str
    policy_hash: str
    # 4. risk profile
    max_risk_level: int = Field(ge=0, le=4, default=3)
    # 5. sandbox profile
    sandbox: SandboxProfile = Field(default_factory=SandboxProfile)
    # 6. tool/MCP policy
    tool_policy: ChannelPolicy = Field(default_factory=ChannelPolicy)
    # 7. network policy
    network_policy: ChannelPolicy = Field(default_factory=ChannelPolicy)
    # 8. filesystem policy
    filesystem_policy: ChannelPolicy = Field(default_factory=ChannelPolicy)
    # 9. secret policy
    secret_policy: ChannelPolicy = Field(default_factory=ChannelPolicy)
    # 10. output policy
    output_policy: ChannelPolicy = Field(default_factory=ChannelPolicy)
    # 11. semantic adapter (None => unknown-framework fallback: boundary-only)
    semantic_adapter: str | None = None
    # 12. activation state
    activation_state: ActivationState = ActivationState.REGISTERED

    def mandatory_controls_present(self) -> tuple[bool, list[str]]:
        """Activation fails if mandatory controls are absent (§60.14). Fail-closed.

        Every protected channel MUST be mediated and deny direct access, and the
        runtime MUST be sandboxed without unrestricted egress. An absent semantic
        adapter is allowed (unknown-framework fallback: boundary-only context,
        §33) and does NOT lower enforcement.
        """
        missing: list[str] = []
        if not self.sandbox.no_unrestricted_egress:
            missing.append("sandbox.no_unrestricted_egress")
        for name in ("tool_policy", "network_policy", "filesystem_policy",
                     "secret_policy", "output_policy"):
            pol: ChannelPolicy = getattr(self, name)
            if not pol.mediated:
                missing.append(f"{name}.mediated")
            if not pol.deny_direct:
                missing.append(f"{name}.deny_direct")
        return (not missing, missing)
