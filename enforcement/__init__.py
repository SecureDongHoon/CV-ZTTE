"""CV-ZTTE Enforcement Fabric (spec §16-§23, §60.12).

Mandatory-mediation brokers/gateways. Every consequential effect crosses a
broker that observes the real operation, canonicalizes it, independently
recomputes the ActionHash, validates the Decision Token (via an injected
:class:`~enforcement.common.DecisionValidator`, implemented in Phase 8),
compares the exact target/operation/payload constraints, executes only on an
exact match, and emits an Execution Receipt.

Module ↔ spec-tree service mapping (the spec lists hyphenated service dirs; the
importable reference implementation uses underscore module names):

* ``mcp_gateway``      → ``enforcement/mcp-gateway``
* ``egress_proxy``     → ``enforcement/egress-proxy``
* ``file_broker``      → ``enforcement/file-broker``
* ``process_broker``   → ``enforcement/process-broker``
* ``secret_broker``    → ``enforcement/secret-broker``
* ``output_proxy``     → ``enforcement/output-proxy``
* ``message_broker``   → ``enforcement/agent-message-broker``
"""
