"""Generalized canonical AgentAction (spec §6).

One versioned model for every consequential operation. Sensitive payloads
SHOULD be carried as immutable references + hashes rather than duplicated
plaintext (§6, §21). Unknown fields are rejected (``extra="forbid"``, §8).
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit


class ActionType(str, enum.Enum):
    TOOL_CALL = "TOOL_CALL"
    MCP_CALL = "MCP_CALL"
    API_REQUEST = "API_REQUEST"
    DB_OPERATION = "DB_OPERATION"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"
    PROCESS_EXEC = "PROCESS_EXEC"
    SHELL_EXEC = "SHELL_EXEC"
    CODE_EXECUTION = "CODE_EXECUTION"
    NETWORK_REQUEST = "NETWORK_REQUEST"
    USER_OUTPUT = "USER_OUTPUT"
    AGENT_MESSAGE = "AGENT_MESSAGE"
    MEMORY_READ = "MEMORY_READ"
    MEMORY_WRITE = "MEMORY_WRITE"
    SECRET_ACCESS = "SECRET_ACCESS"
    CLOUD_CONTROL_ACTION = "CLOUD_CONTROL_ACTION"
    EXTERNAL_MESSAGE = "EXTERNAL_MESSAGE"
    FHE_ENCRYPT = "FHE_ENCRYPT"
    FHE_COMPUTE = "FHE_COMPUTE"
    FHE_DECRYPT_REQUEST = "FHE_DECRYPT_REQUEST"
    FHE_PARTIAL_DECRYPT = "FHE_PARTIAL_DECRYPT"
    FHE_COMBINE_DECRYPT = "FHE_COMBINE_DECRYPT"
    FHE_KEY_ROTATE = "FHE_KEY_ROTATE"
    FHE_CONTEXT_CREATE = "FHE_CONTEXT_CREATE"
    # Optional extension (spec §6, §60.21)
    FHE_REENCRYPT = "FHE_REENCRYPT"


class DataClassification(str, enum.Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"


class PayloadRef(BaseModel):
    """Immutable reference + hash for sensitive payloads (spec §6)."""

    model_config = ConfigDict(extra="forbid")

    ref: str
    hash: str  # "sha256:..." commitment over the referenced content
    size: int | None = None


class AgentAction(BaseModel):
    """Canonical consequential action.

    The ActionHash is a domain-separated commitment over the JCS-canonical
    bytes of this action (spec §8); it is recomputed independently by the
    enforcement point (§16) and can never be supplied by the agent as trusted.
    """

    model_config = ConfigDict(extra="forbid")

    action_version: int = 1
    action_type: ActionType
    target: str
    operation: str | None = None
    resource: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    data_classification: DataClassification = DataClassification.INTERNAL
    # Prefer references over inline plaintext for sensitive content.
    payload_ref: PayloadRef | None = None

    def canonical_dict(self) -> dict[str, Any]:
        """Deterministic dict used for hashing/signing (excludes unset Nones)."""
        return self.model_dump(mode="json", exclude_none=True)

    def action_hash(self) -> str:
        """Domain-separated ActionHash over canonical bytes (spec §8)."""
        return commit(Domain.ACTION, self.canonical_dict())
