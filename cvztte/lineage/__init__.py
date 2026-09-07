"""Confidential data lineage (spec §60.24, §60.10).

Tamper-evident provenance for CAC: it links, using **hashes and IDs only**
(never plaintext),

    plaintext dataset -> ciphertext_id -> program -> encrypted result
                      -> decrypt request -> released result

so any released aggregate can be traced back to the dataset, program, and
approval that produced it. See ``docs/DATA_LINEAGE.md``.
"""

from __future__ import annotations

from cvztte.lineage.graph import LineageGraph
from cvztte.lineage.models import (
    LineageEdge,
    LineageNode,
    LineageNodeType,
    LineageRelation,
)

__all__ = [
    "LineageGraph",
    "LineageEdge",
    "LineageNode",
    "LineageNodeType",
    "LineageRelation",
]
