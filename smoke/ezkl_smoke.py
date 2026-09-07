#!/usr/bin/env python3
"""Phase 0 feasibility smoke test: EZKL ZKML prove/verify (spec §30).

Pipeline: PyTorch -> ONNX -> settings -> SRS -> compile -> setup -> witness
-> proof -> verify. Asserts a valid proof verifies and a TAMPERED proof is
rejected (fail closed). Proves the toolchain is functional only; it does NOT
prove semantic correctness of any Judge (spec §30 caveat).

Several EZKL bindings are async (pyo3-asyncio) and require a running event
loop, so the whole pipeline runs under asyncio and awaits any awaitable result.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import pathlib
import sys
import tempfile

import ezkl
import torch
import torch.nn as nn


class Tiny(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = nn.Linear(4, 3)

    def forward(self, x):
        return self.fc(x)


async def call(fn, **kw):
    """Call an EZKL function; await it if it returns an awaitable."""
    r = fn(**kw)
    if inspect.isawaitable(r):
        return await r
    return r


async def run() -> int:
    work = pathlib.Path(tempfile.mkdtemp(prefix="ezkl_smoke_"))
    model_onnx = work / "model.onnx"
    settings = work / "settings.json"
    compiled = work / "model.compiled"
    vk = work / "vk.key"
    pk = work / "pk.key"
    witness = work / "witness.json"
    proof = work / "proof.json"
    data = work / "input.json"

    torch.manual_seed(0)
    model = Tiny().eval()
    x = torch.tensor([[0.1, 0.2, 0.3, 0.4]], dtype=torch.float32)

    torch.onnx.export(model, x, model_onnx.as_posix(), input_names=["input"],
                      output_names=["output"], opset_version=17, dynamo=False)
    data.write_text(json.dumps({"input_data": [x.flatten().tolist()]}))

    await call(ezkl.gen_settings, model=model_onnx.as_posix(), output=settings.as_posix())
    await call(ezkl.compile_circuit, model=model_onnx.as_posix(),
               compiled_circuit=compiled.as_posix(), settings_path=settings.as_posix())
    await call(ezkl.get_srs, settings_path=settings.as_posix())
    await call(ezkl.setup, model=compiled.as_posix(), vk_path=vk.as_posix(), pk_path=pk.as_posix())
    await call(ezkl.gen_witness, data=data.as_posix(), model=compiled.as_posix(),
               output=witness.as_posix())
    await call(ezkl.prove, witness=witness.as_posix(), model=compiled.as_posix(),
               pk_path=pk.as_posix(), proof_path=proof.as_posix())

    ok = await call(ezkl.verify, proof_path=proof.as_posix(),
                    settings_path=settings.as_posix(), vk_path=vk.as_posix())
    if not ok:
        print("[ezkl] FAIL: valid proof rejected", file=sys.stderr)
        return 1
    print("[ezkl] PASS: valid proof verified")

    # Tamper the real proof bytes -> verify MUST fail. EZKL verifies the integer
    # byte list under "proof" (not the informational "hex_proof" string).
    pj = json.loads(proof.read_text())
    proof_bytes = pj["proof"]
    assert isinstance(proof_bytes, list) and len(proof_bytes) > 10, "unexpected proof shape"
    i = len(proof_bytes) // 2
    proof_bytes[i] = (proof_bytes[i] + 1) % 256
    pj["proof"] = proof_bytes
    bad = work / "proof_bad.json"
    bad.write_text(json.dumps(pj))
    try:
        bad_ok = await call(ezkl.verify, proof_path=bad.as_posix(),
                            settings_path=settings.as_posix(), vk_path=vk.as_posix())
    except Exception:
        bad_ok = False
    if bad_ok:
        print("[ezkl] FAIL: tampered proof accepted (SECURITY)", file=sys.stderr)
        return 1
    print("[ezkl] PASS: tampered proof rejected")
    print("[ezkl] SMOKE OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
