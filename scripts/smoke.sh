#!/usr/bin/env bash
# Acceptance smoke test for agentlock-cli v0.1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Use a release binary if it exists; otherwise build debug.
BIN="${ROOT}/target/release/agentlock"
if [ ! -x "$BIN" ]; then
  cargo build -p agentlock-cli >/dev/null
  BIN="${ROOT}/target/debug/agentlock"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { printf "\n\033[1;36m== %s ==\033[0m\n" "$1"; }

step "doctor"
"$BIN" doctor >/dev/null

step "validate examples"
"$BIN" validate ./examples/claims-agent --level strict
"$BIN" validate ./examples/support-agent --level strict
"$BIN" validate ./examples/trading-risk-agent --level strict

step "build claims bundle"
"$BIN" build ./examples/claims-agent --output "$WORK/claims.bundle.tar.zst"

step "hash + inspect"
"$BIN" hash "$WORK/claims.bundle.tar.zst"
"$BIN" inspect "$WORK/claims.bundle.tar.zst"

step "replay claims"
"$BIN" replay "$WORK/claims.bundle.tar.zst" \
    ./examples/claims-agent/traces/synthetic_claim_traces.jsonl \
    --output "$WORK/replay.json"

step "attest unsigned + verify"
"$BIN" attest "$WORK/claims.bundle.tar.zst" \
    --replay-report "$WORK/replay.json" \
    --output "$WORK/attestation.json"
"$BIN" verify "$WORK/attestation.json"

step "ATEP init + verify"
"$BIN" atep init "$WORK/atep" \
    --agent-id agent://example/smoke \
    --signing-key "$WORK/key.pem"
"$BIN" atep verify "$WORK/atep" --public-key "$WORK/key.pem.pub"
"$BIN" atep inspect "$WORK/atep" >/dev/null

printf "\n\033[1;32mall green\033[0m\n"
