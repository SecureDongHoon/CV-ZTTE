"""Lineage graph / recorder (spec §60.24).

A thread-safe, tamper-evident provenance DAG for CAC. Records are appended from
the CAC envelopes and decrypt/release events; the graph stores only hashes and
IDs. :meth:`LineageGraph.trace` reconstructs the full chain behind any node, and
:meth:`LineageGraph.graph_hash` is a domain-separated commitment over the ordered
records so tampering is detectable.

This recorder does not itself authorize anything — it is the audit/provenance
substrate the control plane (Phase 17) and Confidential Query Governance consult.
"""

from __future__ import annotations

import threading

from cvztte.canonical.domains import Domain
from cvztte.canonical.hashing import commit
from cvztte.lineage.models import (
    LineageEdge,
    LineageNode,
    LineageNodeType,
    LineageRelation,
)


class LineageGraph:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nodes: dict[str, LineageNode] = {}
        #: Insertion-ordered edge list (drives the tamper-evident graph hash).
        self._edges: list[LineageEdge] = []
        self._edge_set: set[tuple[str, str, str]] = set()

    # -- primitive graph ops ------------------------------------------------

    def _add_node(self, node: LineageNode) -> str:
        node_id = node.node_id()
        # Idempotent by (type, ref). The same logical object may be recorded
        # once with its hash/attributes and again as a bare reference (e.g. a
        # ciphertext named as a compute input); keep the richer record so
        # provenance metadata is not lost regardless of recording order.
        existing = self._nodes.get(node_id)
        if existing is None or self._richer(node, existing):
            self._nodes[node_id] = node
        return node_id

    @staticmethod
    def _richer(candidate: LineageNode, existing: LineageNode) -> bool:
        """A node carrying a hash/attributes supersedes a bare reference."""
        cand = (candidate.ref_hash is not None, len(candidate.attributes))
        curr = (existing.ref_hash is not None, len(existing.attributes))
        return cand > curr

    def _add_edge(self, src: str, dst: str, relation: LineageRelation) -> None:
        key = (src, dst, relation.value)
        if key in self._edge_set:
            return
        self._edge_set.add(key)
        self._edges.append(LineageEdge(src=src, dst=dst, relation=relation))

    # -- recording from CAC events (§60.24) --------------------------------

    def record_ciphertext(
        self,
        *,
        dataset_id: str,
        ciphertext_id: str,
        ciphertext_hash: str,
        classification: str,
        context_id: str,
        key_epoch: int,
    ) -> str:
        """dataset -> ciphertext. Returns the ciphertext node id."""
        with self._lock:
            ds = self._add_node(
                LineageNode(node_type=LineageNodeType.DATASET, ref=dataset_id)
            )
            ct = self._add_node(
                LineageNode(
                    node_type=LineageNodeType.CIPHERTEXT,
                    ref=ciphertext_id,
                    ref_hash=ciphertext_hash,
                    attributes={
                        "classification": classification,
                        "context_id": context_id,
                        "key_epoch": str(key_epoch),
                    },
                )
            )
            self._add_edge(ds, ct, LineageRelation.ENCRYPTS)
            return ct

    def record_result(
        self,
        *,
        parent_ciphertext_ids: list[str],
        program_id: str,
        program_version: str,
        result_id: str,
        result_hash: str,
        lineage_id: str,
    ) -> str:
        """parent ciphertext(s) -> program -> result. Returns the result node id."""
        with self._lock:
            prog = self._add_node(
                LineageNode(
                    node_type=LineageNodeType.PROGRAM,
                    ref=program_id,
                    attributes={"version": program_version},
                )
            )
            for pid in parent_ciphertext_ids:
                ct = self._add_node(
                    LineageNode(node_type=LineageNodeType.CIPHERTEXT, ref=pid)
                )
                self._add_edge(ct, prog, LineageRelation.COMPUTED_BY)
            res = self._add_node(
                LineageNode(
                    node_type=LineageNodeType.RESULT,
                    ref=result_id,
                    ref_hash=result_hash,
                    attributes={"lineage_id": lineage_id},
                )
            )
            self._add_edge(prog, res, LineageRelation.PRODUCES)
            return res

    def record_decrypt_request(
        self, *, result_id: str, request_id: str, requester: str, purpose: str
    ) -> str:
        """result -> decrypt request. Returns the request node id."""
        with self._lock:
            res = self._add_node(
                LineageNode(node_type=LineageNodeType.RESULT, ref=result_id)
            )
            req = self._add_node(
                LineageNode(
                    node_type=LineageNodeType.DECRYPT_REQUEST,
                    ref=request_id,
                    attributes={"requester": requester, "purpose": purpose},
                )
            )
            self._add_edge(res, req, LineageRelation.DECRYPT_OF)
            return req

    def record_release(
        self,
        *,
        request_id: str,
        release_id: str,
        recipient: str,
        released_hash: str | None = None,
        approval_id: str | None = None,
    ) -> str:
        """decrypt request -> released result. Returns the release node id."""
        attrs = {"recipient": recipient}
        if approval_id:
            attrs["approval_id"] = approval_id
        with self._lock:
            req = self._add_node(
                LineageNode(node_type=LineageNodeType.DECRYPT_REQUEST, ref=request_id)
            )
            rel = self._add_node(
                LineageNode(
                    node_type=LineageNodeType.RELEASED_RESULT,
                    ref=release_id,
                    ref_hash=released_hash,
                    attributes=attrs,
                )
            )
            self._add_edge(req, rel, LineageRelation.RELEASES)
            return rel

    # -- queries ------------------------------------------------------------

    def get_node(self, node_id: str) -> LineageNode | None:
        with self._lock:
            return self._nodes.get(node_id)

    def trace(self, node_id: str) -> list[LineageNode]:
        """Return the ancestor chain of ``node_id`` (roots first, node last)."""
        with self._lock:
            parents: dict[str, list[str]] = {}
            for e in self._edges:
                parents.setdefault(e.dst, []).append(e.src)
            order: list[str] = []
            seen: set[str] = set()

            def visit(nid: str) -> None:
                if nid in seen:
                    return
                seen.add(nid)
                for p in parents.get(nid, []):
                    visit(p)
                order.append(nid)

            visit(node_id)
            return [self._nodes[n] for n in order if n in self._nodes]

    def graph_hash(self) -> str:
        """Tamper-evident commitment over the ordered nodes + edges."""
        with self._lock:
            payload = {
                "nodes": sorted(
                    (
                        {
                            "id": nid,
                            "type": n.node_type.value,
                            "ref": n.ref,
                            "ref_hash": n.ref_hash,
                            "attributes": n.attributes,
                        }
                        for nid, n in self._nodes.items()
                    ),
                    key=lambda d: d["id"],
                ),
                "edges": [
                    {"src": e.src, "dst": e.dst, "relation": e.relation.value}
                    for e in self._edges
                ],
            }
            return commit(Domain.LINEAGE_GRAPH, payload)
