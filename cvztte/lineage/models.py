"""Lineage node/edge models (spec §60.24).

Every node stores a **reference and/or hash**, never sensitive plaintext
(§60.24: "Store hashes/IDs rather than sensitive plaintext"). Node ids are
domain-separated commitments so the same logical object maps to a stable id and
the graph is tamper-evident.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit


class LineageNodeType(str, enum.Enum):
    """The provenance chain node kinds (§60.24)."""

    DATASET = "DATASET"
    CIPHERTEXT = "CIPHERTEXT"
    PROGRAM = "PROGRAM"
    RESULT = "RESULT"
    DECRYPT_REQUEST = "DECRYPT_REQUEST"
    RELEASED_RESULT = "RELEASED_RESULT"


class LineageRelation(str, enum.Enum):
    """Directed edge kinds along the provenance chain."""

    ENCRYPTS = "ENCRYPTS"           # dataset  -> ciphertext
    COMPUTED_BY = "COMPUTED_BY"     # ciphertext -> program
    PRODUCES = "PRODUCES"           # program  -> result
    DECRYPT_OF = "DECRYPT_OF"       # result   -> decrypt_request
    RELEASES = "RELEASES"           # decrypt_request -> released_result


class LineageNode(BaseModel):
    """An immutable provenance node keyed by a domain-separated id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    node_type: LineageNodeType
    #: Stable business identifier (dataset id, ciphertext id, program id, ...).
    ref: str
    #: Optional hash pinning the referenced artifact (e.g. ciphertext hash).
    ref_hash: str | None = None
    #: Non-sensitive attributes only (classification label, version, epoch);
    #: never plaintext, key material, or raw values (§60.24).
    attributes: dict[str, str] = Field(default_factory=dict)

    def node_id(self) -> str:
        """Domain-separated commitment identifying this node.

        Identity is *what the node refers to* — its ``node_type`` and business
        ``ref`` — so the same logical object referenced from two places (e.g. a
        ciphertext recorded once with its hash, then named again as a compute
        input) maps to one node and the provenance DAG stays connected. The
        pinned ``ref_hash`` and ``attributes`` are metadata carried on the node
        and are committed into :meth:`LineageGraph.graph_hash` for
        tamper-evidence, not into node identity.
        """
        return commit(
            Domain.LINEAGE_NODE,
            {
                "node_type": self.node_type.value,
                "ref": self.ref,
            },
        )


class LineageEdge(BaseModel):
    """A directed provenance edge between two node ids."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    src: str
    dst: str
    relation: LineageRelation
