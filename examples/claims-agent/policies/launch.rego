# OPA / Rego launch policy for the Claims Agent.
#
# Evaluated by `agenomic policy eval` and, when the bundle declares an
# `execution:` block, as a fail-closed gate inside `agenomic run`. The input
# document is the launch context derived from the genome (see
# `docs/command-reference.md`).
#
# Contract: `allow` defaults to false (fail-closed); `deny[msg]` lists
# violations. Final decision is `allow == true AND deny is empty`.
package agenomic

default allow := false

# A launch is permitted when the agent declares its criticality and does not
# request open network egress.
allow if {
	input.criticality != ""
	count(object.get(input, "network_allow", [])) == 0
}

# High-criticality agents must never declare unrestricted network egress.
deny contains msg if {
	input.criticality == "high"
	count(object.get(input, "network_allow", [])) > 0
	msg := "high-criticality agent must not declare open network egress"
}
