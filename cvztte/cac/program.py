"""FHE Program Registry (spec §39).

Only allowlisted programs may run over ciphertext — there is **no arbitrary
agent-uploaded computation** by default (§39). Each program carries a manifest
(input schema, scheme, depth, shapes, implementation hash, leakage notes,
benchmark, policy classification) and is pinned by a domain-separated hash. The
native broker refuses any ``program_id`` not in the registry.
"""

from __future__ import annotations

import enum
import threading

from pydantic import BaseModel, ConfigDict, Field

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.cac.context import FHEScheme
from cvztte.errors import CVZTTEError, ErrorCode


class ProgramId(str, enum.Enum):
    """The reference allowlist (§39). CKKS-safe leveled arithmetic only."""

    SUM_V1 = "SUM_V1"
    AVERAGE_V1 = "AVERAGE_V1"
    WEIGHTED_SCORE_V1 = "WEIGHTED_SCORE_V1"


class FHEProgram(BaseModel):
    """An allowlisted program manifest (spec §39)."""

    model_config = ConfigDict(extra="forbid")

    program_id: ProgramId
    version: str = "1"
    scheme: FHEScheme = FHEScheme.CKKS
    #: Multiplicative depth the program consumes (must fit within the context).
    depth: int = Field(ge=0)
    #: Number of input ciphertexts the program consumes.
    input_arity: int = Field(ge=1, default=1)
    input_schema: str
    #: Implementation hash: pins the native op sequence this program names.
    implementation_hash: str
    leakage_notes: str
    policy_classification: str
    #: Whether the program needs a weight vector (WEIGHTED_SCORE_V1) / count (AVERAGE_V1).
    requires_weights: bool = False
    requires_count: bool = False

    def program_hash(self) -> str:
        return commit(
            Domain.FHE_PROGRAM,
            {
                "program_id": self.program_id.value,
                "version": self.version,
                "scheme": self.scheme.value,
                "depth": self.depth,
                "input_arity": self.input_arity,
                "input_schema": self.input_schema,
                "implementation_hash": self.implementation_hash,
                "policy_classification": self.policy_classification,
            },
        )


def default_programs() -> list[FHEProgram]:
    """The reference §39 allowlist for the Phase 14 CKKS foundation."""
    return [
        FHEProgram(
            program_id=ProgramId.SUM_V1,
            depth=0,
            input_arity=1,
            input_schema="vector<double>[batch]",
            implementation_hash="op:evalsum",
            leakage_notes="reveals only the aggregate sum on decrypt",
            policy_classification="aggregate",
        ),
        FHEProgram(
            program_id=ProgramId.AVERAGE_V1,
            depth=1,
            input_arity=1,
            input_schema="vector<double>[batch]",
            implementation_hash="op:evalsum;evalmult(scalar)",
            leakage_notes="reveals only the mean on decrypt; min group size enforced by query governance",
            policy_classification="aggregate",
            requires_count=True,
        ),
        FHEProgram(
            program_id=ProgramId.WEIGHTED_SCORE_V1,
            depth=1,
            input_arity=1,
            input_schema="vector<double>[batch] * weights[batch]",
            implementation_hash="op:evalmult(ptxt);evalsum",
            leakage_notes="reveals only the weighted aggregate on decrypt",
            policy_classification="aggregate",
            requires_weights=True,
        ),
    ]


class FHEProgramRegistry:
    """Holds the allowlisted programs. An unlisted program_id is refused (§39)."""

    def __init__(self, programs: list[FHEProgram] | None = None) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[ProgramId, FHEProgram] = {}
        for p in programs if programs is not None else default_programs():
            self._by_id[p.program_id] = p

    def register(self, program: FHEProgram) -> str:
        with self._lock:
            self._by_id[program.program_id] = program
        return program.program_hash()

    def get(self, program_id: ProgramId) -> FHEProgram:
        with self._lock:
            prog = self._by_id.get(program_id)
        if prog is None:
            raise CVZTTEError(ErrorCode.FHE_PROGRAM_UNKNOWN, "program not allowlisted")
        return prog

    def require(self, program_id: ProgramId, *, context_depth: int) -> FHEProgram:
        """Resolve a program and reject if it exceeds the context depth (fail-closed)."""
        prog = self.get(program_id)
        if prog.depth > context_depth:
            raise CVZTTEError(
                ErrorCode.FHE_PROGRAM_DENIED,
                "program depth exceeds context multiplicative depth",
            )
        return prog
