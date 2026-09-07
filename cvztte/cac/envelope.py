"""Ciphertext and result envelopes (spec §38).

Every ciphertext carries a metadata envelope binding it to its dataset, context,
key epoch, schema, classification, owner, content hash, and the set of programs
it may feed. A result envelope additionally records its lineage: the parent
ciphertext IDs, the program id/version, the result ciphertext hash, and a lineage
id. Context / key-epoch / ciphertext substitution is rejected (§38, fail-closed).

The ``ciphertext_hash`` is a domain-separated commitment over the *serialized
ciphertext bytes* produced by the native broker — it pins the actual crypto
object, not just its metadata.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cvztte.action.model import DataClassification
from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.errors import CVZTTEError, ErrorCode


class CiphertextEnvelope(BaseModel):
    """Ciphertext metadata envelope (spec §38)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    dataset_id: str
    ciphertext_id: str
    context_id: str
    context_hash: str
    key_epoch: int = Field(ge=0)
    schema_: str = Field(alias="schema")
    classification: DataClassification
    owner: str
    #: Domain-separated hash over the serialized ciphertext bytes.
    ciphertext_hash: str
    created_at: str
    #: The set of program ids this ciphertext may be fed to (sorted).
    allowed_programs: list[str] = Field(default_factory=list)
    #: Hash of the allowed-program set (§38); binds membership tamper-evidently.
    allowed_program_set_hash: str

    def envelope_hash(self) -> str:
        return commit(
            Domain.FHE_CIPHERTEXT,
            self.model_dump(mode="json", by_alias=True),
        )

    def allows_program(self, program_id: str) -> bool:
        return program_id in self.allowed_programs


class ResultEnvelope(BaseModel):
    """Result envelope — a ciphertext envelope plus lineage (spec §38)."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    dataset_id: str
    ciphertext_id: str
    context_id: str
    context_hash: str
    key_epoch: int = Field(ge=0)
    schema_: str = Field(alias="schema")
    classification: DataClassification
    owner: str
    ciphertext_hash: str
    created_at: str
    allowed_program_set_hash: str
    # -- lineage (§38) --
    parent_ciphertext_ids: list[str]
    program_id: str
    program_version: str
    result_ciphertext_hash: str
    lineage_id: str

    def envelope_hash(self) -> str:
        return commit(Domain.FHE_RESULT, self.model_dump(mode="json", by_alias=True))


def assert_no_substitution(
    envelope: CiphertextEnvelope,
    *,
    expected_context_id: str,
    expected_context_hash: str,
    expected_key_epoch: int,
) -> None:
    """Reject context / key-epoch / ciphertext substitution (§38, fail-closed)."""
    if envelope.context_id != expected_context_id:
        raise CVZTTEError(
            ErrorCode.FHE_CONTEXT_MISMATCH, "ciphertext bound to a different context"
        )
    if envelope.context_hash != expected_context_hash:
        raise CVZTTEError(
            ErrorCode.FHE_CONTEXT_MISMATCH, "ciphertext context hash mismatch"
        )
    if envelope.key_epoch != expected_key_epoch:
        raise CVZTTEError(
            ErrorCode.FHE_KEY_EPOCH_MISMATCH, "ciphertext key epoch mismatch"
        )
