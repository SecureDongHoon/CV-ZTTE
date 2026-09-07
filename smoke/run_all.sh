#!/usr/bin/env bash
# Phase 0 feasibility gate: run every foundation smoke test (spec §0.7, §54 Phase 0).
# Fails closed: any single failure aborts with nonzero exit.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/env.sh"

pass=0; fail=0
run() {
  local name="$1"; shift
  echo "==================== $name ===================="
  if "$@"; then echo "-> $name PASS"; pass=$((pass+1));
  else echo "-> $name FAIL"; fail=$((fail+1)); fi
  echo
}

run "openssl-mldsa" bash "$HERE/openssl_mldsa_smoke.sh" ML-DSA-65
run "redis-atomic"  bash "$HERE/run_redis_smoke.sh"
run "opa"           bash -c "opa eval -f raw -d '$HERE/opa_smoke.rego' 'data.cvztte.smoke.decision.allow' -I <<<'{\"capability\":\"read\",\"data_classification\":\"INTERNAL\"}' | grep -q true"
run "gnark-groth16" bash -c "cd '$HERE/gnark' && go run . >/dev/null 2>&1"
run "ezkl"          python "$HERE/ezkl_smoke.py"
run "openfhe"       bash -c "LD_LIBRARY_PATH='$HOME/opt/openfhe/lib:${LD_LIBRARY_PATH:-}' '$HERE/openfhe/build/smoke_openfhe' >/dev/null 2>&1"

echo "======================================================"
echo "SMOKE SUMMARY: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
echo "ALL FOUNDATION SMOKE TESTS PASS"
