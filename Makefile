# CV-ZTTE reference build — convenience targets.
# Always `source env.sh` first so the user-local toolchain + venv are on PATH.
# This is a reference build; nothing here is production-certified (see
# docs/DEPLOYMENT.md, docs/FINAL_SECURITY_REVIEW.md §29).

.PHONY: help smoke test test-all test-native gateway demo demo-egress demo-output \
        demo-tool build-zk fmt lint clean

help:
	@echo "CV-ZTTE make targets (run 'source env.sh' first):"
	@echo "  smoke        - Phase 0 feasibility gate"
	@echo "  test         - pytest, excluding slow native micro-benchmarks"
	@echo "  test-all     - full pytest (includes @slow native benchmarks)"
	@echo "  test-native  - only the @slow native OpenFHE/gnark benchmarks"
	@echo "  build-zk     - build the Go gnark zk-authz service binary"
	@echo "  gateway      - run the reference Control-Plane HTTP gateway"
	@echo "  demo         - run the full-stack agent demo (Demo A + E)"
	@echo "  demo-tool    - protected-tool mandatory-mediation demo"
	@echo "  demo-egress  - egress-proxy boundary-controls demo"
	@echo "  demo-output  - output-proxy DLP demo"

smoke:
	bash smoke/run_all.sh

test:
	python -m pytest tests/ -m "not slow"

test-all:
	python -m pytest tests/

test-native:
	python -m pytest tests/ -m slow

build-zk:
	cd services/zk-authz && go build -o bin/zk-authz ./cmd/...

gateway:
	python apps/gateway/server.py

demo:
	python apps/agent-demo/demo.py

demo-tool:
	python apps/protected-tool/run.py

demo-egress:
	python apps/egress-proxy/run.py

demo-output:
	python apps/output-proxy/run.py

fmt:
	python -m ruff format cvztte enforcement tests apps || true

lint:
	python -m ruff check cvztte enforcement tests apps || true

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .gateway-keystore
