#!/usr/bin/env bash
# Checks every envoy/testdata/*.golden.json with a real Envoy
# (`envoy --mode validate`), so a translation Envoy would reject fails here
# rather than in a sandbox. ENVOY_IMAGE picks the version.
set -euo pipefail
ENVOY_IMAGE="${ENVOY_IMAGE:-docker.io/envoyproxy/envoy:v1.36.2}"
cd "$(dirname "$0")/.."
rc=0
for f in envoy/testdata/*.golden.json; do
	if docker run --rm -v "$PWD/envoy/testdata:/cfg:ro" "$ENVOY_IMAGE" \
		--mode validate -c "/cfg/$(basename "$f")" --log-level warn >/dev/null 2>/tmp/envoy-validate.err; then
		echo "ok   $f ($ENVOY_IMAGE)"
	else
		echo "FAIL $f ($ENVOY_IMAGE)"; cat /tmp/envoy-validate.err; rc=1
	fi
done
exit $rc
