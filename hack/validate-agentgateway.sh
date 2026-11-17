#!/usr/bin/env bash
# Loads the translator's real output for every agentgateway/testdata/*.intent.json
# in a real agentgateway (`--validate-only`), so a configuration agentgateway
# would reject fails here rather than in a sandbox. AGENTGATEWAY_IMAGE picks
# the version.
set -euo pipefail
AGENTGATEWAY_IMAGE="${AGENTGATEWAY_IMAGE:-cr.agentgateway.dev/agentgateway:v1.7.0}"
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -o "$work/egress-translator" ./cmd/egress-translator
rc=0
for f in agentgateway/testdata/*.intent.json; do
	n=$(basename "$f" .intent.json)
	mkdir -p "$work/$n"
	"$work/egress-translator" agentgateway --intent "$f" --out "$work/$n/agentgateway.json" >/dev/null
	chmod -R a+rX "$work"
	if docker run --rm -v "$work/$n:/cfg:ro" "$AGENTGATEWAY_IMAGE" \
		-f /cfg/agentgateway.json --validate-only >"$work/out" 2>&1; then
		echo "ok   $f ($AGENTGATEWAY_IMAGE)"
	else
		echo "FAIL $f ($AGENTGATEWAY_IMAGE)"; cat "$work/out"; rc=1
	fi
done
exit $rc
