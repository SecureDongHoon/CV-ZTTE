"""Unit tests for confidential data lineage (spec §60.24)."""

from __future__ import annotations

from cvztte.lineage import LineageGraph, LineageNodeType


def _full_chain(g: LineageGraph):
    ct = g.record_ciphertext(
        dataset_id="ds-employees",
        ciphertext_id="ct_1",
        ciphertext_hash="sha256:aa",
        classification="CONFIDENTIAL",
        context_id="ckks-v1",
        key_epoch=1,
    )
    res = g.record_result(
        parent_ciphertext_ids=["ct_1"],
        program_id="SUM_V1",
        program_version="1",
        result_id="res_1",
        result_hash="sha256:bb",
        lineage_id="lin_1",
    )
    req = g.record_decrypt_request(
        result_id="res_1", request_id="req_1", requester="sec-supervisor", purpose="review"
    )
    rel = g.record_release(
        request_id="req_1", release_id="rel_1", recipient="sec-supervisor", approval_id="appr_1"
    )
    return ct, res, req, rel


def test_trace_reconstructs_full_provenance_chain():
    g = LineageGraph()
    _, _, _, rel = _full_chain(g)
    chain = g.trace(rel)
    types = [n.node_type for n in chain]
    # roots first, released result last (§60.24 chain order).
    assert types == [
        LineageNodeType.DATASET,
        LineageNodeType.CIPHERTEXT,
        LineageNodeType.PROGRAM,
        LineageNodeType.RESULT,
        LineageNodeType.DECRYPT_REQUEST,
        LineageNodeType.RELEASED_RESULT,
    ]


def test_node_ids_are_idempotent():
    g = LineageGraph()
    a = g.record_ciphertext(
        dataset_id="ds", ciphertext_id="ct_1", ciphertext_hash="sha256:aa",
        classification="INTERNAL", context_id="c", key_epoch=1,
    )
    b = g.record_ciphertext(
        dataset_id="ds", ciphertext_id="ct_1", ciphertext_hash="sha256:aa",
        classification="INTERNAL", context_id="c", key_epoch=1,
    )
    assert a == b


def test_graph_hash_changes_when_lineage_grows():
    g = LineageGraph()
    _full_chain(g)
    h1 = g.graph_hash()
    g.record_release(
        request_id="req_1", release_id="rel_2", recipient="analyst"
    )
    assert g.graph_hash() != h1
    assert h1.startswith("sha256:")


def test_no_plaintext_stored_only_refs_and_hashes():
    g = LineageGraph()
    _, _, _, rel = _full_chain(g)
    for node in g.trace(rel):
        # Only ids/hashes/labels — never raw values.
        assert node.ref_hash is None or node.ref_hash.startswith("sha256:")
