# CV-ZTTE authoritative hard policy (spec §13, §60.4).
#
# OPA is authoritative for deterministic rules: capability, action type,
# resource/path/domain scope, classification, row/byte limits, external-network
# prohibition, shell/secret permission, risk floor, and required controls.
# Hard DENY is final (spec §13): if any violation holds, `allow` is false and
# no risk logic can re-enable it.
#
# Input schema (built by cvztte.policy.opa_input):
#   input.action = {action_type, operation, resource, data_classification,
#                   destination_domain?, row_count?, byte_count?}
#   input.grant  = {capabilities[], resource_scopes[], clearance,
#                   allow_external_network, network_allowlist[],
#                   shell_permitted, secret_access_permitted,
#                   max_db_rows, max_external_bytes}
package cvztte.authz

import rego.v1

# ---------------------------------------------------------------------------
# classification / clearance ordering
# ---------------------------------------------------------------------------
class_rank := {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}

action_class := class_rank[input.action.data_classification]

clearance := class_rank[input.grant.clearance]

# ---------------------------------------------------------------------------
# capability required by each action type
# ---------------------------------------------------------------------------
required_capability := cap if {
	input.action.action_type == "DB_OPERATION"
	input.action.operation == "read"
	cap := "db:read"
} else := cap if {
	input.action.action_type == "DB_OPERATION"
	cap := "db:write"
} else := cap if {
	cap := static_cap[input.action.action_type]
} else := "unknown:capability"

static_cap := {
	"FILE_READ": "fs:read",
	"MEMORY_READ": "memory:read",
	"FILE_WRITE": "fs:write",
	"FILE_DELETE": "fs:write",
	"MEMORY_WRITE": "memory:write",
	"NETWORK_REQUEST": "net:external",
	"API_REQUEST": "net:external",
	"EXTERNAL_MESSAGE": "net:external",
	"AGENT_MESSAGE": "agent:message",
	"USER_OUTPUT": "output:user",
	"TOOL_CALL": "tool:call",
	"MCP_CALL": "tool:call",
	"CLOUD_CONTROL_ACTION": "cloud:control",
	"PROCESS_EXEC": "shell:exec",
	"SHELL_EXEC": "shell:exec",
	"CODE_EXECUTION": "shell:exec",
	"SECRET_ACCESS": "secret:read",
	"FHE_ENCRYPT": "fhe:encrypt",
	"FHE_COMPUTE": "fhe:compute",
	"FHE_DECRYPT_REQUEST": "fhe:decrypt",
	"FHE_PARTIAL_DECRYPT": "fhe:decrypt",
	"FHE_COMBINE_DECRYPT": "fhe:decrypt",
	"FHE_REENCRYPT": "fhe:compute",
	"FHE_KEY_ROTATE": "fhe:admin",
	"FHE_CONTEXT_CREATE": "fhe:admin",
}

# ---------------------------------------------------------------------------
# action classes (used for tiering and specific gates)
# ---------------------------------------------------------------------------
is_network if input.action.action_type in {"NETWORK_REQUEST", "API_REQUEST", "EXTERNAL_MESSAGE"}

is_shell if input.action.action_type in {"PROCESS_EXEC", "SHELL_EXEC", "CODE_EXECUTION"}

is_secret if input.action.action_type == "SECRET_ACCESS"

is_decrypt if input.action.action_type in {"FHE_DECRYPT_REQUEST", "FHE_PARTIAL_DECRYPT", "FHE_COMBINE_DECRYPT"}

is_write if input.action.action_type in {"FILE_WRITE", "FILE_DELETE", "MEMORY_WRITE"}

is_db_write if {
	input.action.action_type == "DB_OPERATION"
	input.action.operation != "read"
}

# ---------------------------------------------------------------------------
# violations (hard-deny reasons). Any element => allow is false.
# ---------------------------------------------------------------------------
violation contains "CAPABILITY_MISSING" if {
	not required_capability in input.grant.capabilities
}

violation contains "SCOPE_NOT_COVERED" if {
	not scope_covered
}

scope_covered if {
	some s in input.grant.resource_scopes
	startswith(input.action.resource, s)
}

violation contains "CLEARANCE_INSUFFICIENT" if {
	action_class > clearance
}

violation contains "EXTERNAL_NETWORK_FORBIDDEN" if {
	is_network
	not input.grant.allow_external_network
}

violation contains "DOMAIN_NOT_ALLOWLISTED" if {
	is_network
	not input.action.destination_domain in input.grant.network_allowlist
}

violation contains "SHELL_FORBIDDEN" if {
	is_shell
	not input.grant.shell_permitted
}

violation contains "SECRET_ACCESS_FORBIDDEN" if {
	is_secret
	not input.grant.secret_access_permitted
}

violation contains "DB_ROW_LIMIT_EXCEEDED" if {
	input.action.row_count > input.grant.max_db_rows
}

violation contains "EXTERNAL_BYTE_LIMIT_EXCEEDED" if {
	input.action.byte_count > input.grant.max_external_bytes
}

# ---------------------------------------------------------------------------
# decision
# ---------------------------------------------------------------------------
default allow := false

allow if count(violation) == 0

reason_code := "ALLOW" if {
	allow
} else := sort(violation)[0]

# Risk tiers L0..L4 (spec §28). Deterministic max of contributions.
risk_candidates contains 0

risk_candidates contains 1 if action_class >= 1

risk_candidates contains 2 if action_class >= 2

risk_candidates contains 2 if input.action.action_type in {"FILE_READ", "DB_OPERATION", "MEMORY_READ"}

risk_candidates contains 3 if is_write

risk_candidates contains 3 if is_db_write

risk_candidates contains 3 if is_network

risk_candidates contains 4 if is_shell

risk_candidates contains 4 if is_secret

risk_candidates contains 4 if is_decrypt

risk_level := max(risk_candidates)

# Required controls scale with risk; risk may ADD controls, never remove the
# mandatory baseline (spec §28). These are the risk-driven additions.
default require_gnark_authz := false

default require_behavior_check := false

default require_ezkl := false

default require_human_approval := false

require_gnark_authz if risk_level >= 3

require_behavior_check if risk_level >= 2

require_ezkl if risk_level >= 3

require_human_approval if risk_level >= 4

decision := {
	"allow": allow,
	"reason_code": reason_code,
	"risk_level": risk_level,
	"require_gnark_authz": require_gnark_authz,
	"require_behavior_check": require_behavior_check,
	"require_ezkl": require_ezkl,
	"require_human_approval": require_human_approval,
}
