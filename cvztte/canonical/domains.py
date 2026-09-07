"""Hash domain-separation tags (spec §8).

Every SHA-256 commitment in CV-ZTTE is domain-separated so that a hash computed
for one object class can never be reinterpreted as another (defends the
"Action A proof/token cannot execute Action B" family of invariants, §4.11).
"""

from __future__ import annotations

import enum


class Domain(str, enum.Enum):
    ACTION = "cvztte.action.v3"
    REQUEST = "cvztte.request.v3"
    POLICY = "cvztte.policy.v3"
    DELEGATION = "cvztte.delegation.v3"
    SESSION = "cvztte.session.v3"
    AUDIT = "cvztte.audit.v3"
    BEHAVIOR_STATE = "cvztte.behavior_state.v3"
    MODEL = "cvztte.model.v3"
    CIRCUIT = "cvztte.circuit.v3"
    FHE_CONTEXT = "cvztte.fhe_context.v3"
    FHE_CIPHERTEXT = "cvztte.fhe_ciphertext.v3"
    FHE_PROGRAM = "cvztte.fhe_program.v3"
    FHE_RESULT = "cvztte.fhe_result.v3"
    EXECUTION_RECEIPT = "cvztte.execution_receipt.v3"
    DECISION_TOKEN = "cvztte.decision_token.v3"
    AUDIT_EVENT = "cvztte.audit_event.v3"
    AUDIT_CHECKPOINT = "cvztte.audit_checkpoint.v3"
    CONTAINMENT_TRANSITION = "cvztte.containment_transition.v3"
    LINEAGE_NODE = "cvztte.lineage_node.v3"
    LINEAGE_GRAPH = "cvztte.lineage_graph.v3"
    QUERY_SUBSET = "cvztte.query_subset.v3"
