"""Policy decision model and risk tiers (spec §13, §28, §60.4)."""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class RiskTier(int, enum.Enum):
    L0 = 0  # observational / public
    L1 = 1  # internal low risk
    L2 = 2  # sensitive read + behavior
    L3 = 3  # write / external / high-value + gnark + behavior + EZKL
    L4 = 4  # secret / shell / destructive / decrypt + strongest + approval


class PolicyDecision(BaseModel):
    """OPA decision (spec §60.4). Hard DENY (``allow == False``) is final."""

    model_config = ConfigDict(extra="forbid")

    allow: bool
    reason_code: str
    risk_level: int = Field(ge=0, le=4)
    require_gnark_authz: bool = False
    require_behavior_check: bool = False
    require_ezkl: bool = False
    require_human_approval: bool = False

    @property
    def tier(self) -> RiskTier:
        return RiskTier(self.risk_level)
