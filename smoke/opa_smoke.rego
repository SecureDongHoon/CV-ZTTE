# Phase 0 feasibility smoke policy (spec §13). Deterministic allow + risk_level.
# OPA 1.x defaults to Rego v1 (if/contains keywords, explicit imports optional).
package cvztte.smoke

default allow := false
default risk_level := 4

# Allow a read of an INTERNAL resource when the capability is granted.
allow if {
	input.capability == "read"
	input.data_classification == "INTERNAL"
}

risk_level := 1 if {
	input.capability == "read"
	input.data_classification == "INTERNAL"
}

decision := {
	"allow": allow,
	"risk_level": risk_level,
	"require_gnark": risk_level >= 3,
	"require_ezkl": risk_level >= 3,
	"require_human_approval": risk_level >= 4,
}
