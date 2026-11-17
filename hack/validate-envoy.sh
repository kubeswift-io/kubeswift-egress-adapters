#!/usr/bin/env bash
# Loads the translator's real output for every envoy/testdata/*.intent.json in
# a real Envoy (`envoy --mode validate`), so a translation Envoy would reject
# fails here rather than in a sandbox. ENVOY_IMAGE picks the version.
#
# Envoy checks that SDS files exist, so the intent's secretsDir is filled with
# a throwaway certificate and values, as KubeSwift fills a warm slot's.
set -euo pipefail
ENVOY_IMAGE="${ENVOY_IMAGE:-docker.io/envoyproxy/envoy:v1.36.2}"
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
go build -o "$work/egress-translator" ./cmd/egress-translator
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=validate \
	-keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null
rc=0
for f in envoy/testdata/*.intent.json; do
	n=$(basename "$f" .intent.json)
	out="$work/$n/out" secrets="$work/$n/secrets"
	mkdir -p "$out" "$secrets"
	"$work/egress-translator" envoy --intent "$f" --out "$out/envoy.json" --admin-port 15000 >/dev/null
	sdir=$(jq -r '.secretsDir // empty' "$f")
	mounts=(-v "$out:/etc/kubeswift/egress-proxy:ro")
	if [ -n "$sdir" ]; then
		for c in $(jq -r '.tls.certificates[]? | .cert' "$f"); do cp "$work/cert.pem" "$secrets/$(basename "$c")"; done
		for k in $(jq -r '.tls.certificates[]? | .key' "$f"); do cp "$work/key.pem" "$secrets/$(basename "$k")"; done
		for v in $(jq -r '.credentials[]? | .headerValueFile // .file' "$f"); do : > "$secrets/$(basename "$v")"; done
		mounts+=(-v "$secrets:$sdir:ro")
	fi
	# The bootstrap names its SDS files by the directory it was written to.
	sed -i "s#$out#/etc/kubeswift/egress-proxy#g" "$out"/*.json
	chmod -R a+rX "$work"
	if docker run --rm "${mounts[@]}" "$ENVOY_IMAGE" \
		--mode validate -c /etc/kubeswift/egress-proxy/envoy.json --log-level warn >/dev/null 2>"$work/err"; then
		echo "ok   $f ($ENVOY_IMAGE)"
	else
		echo "FAIL $f ($ENVOY_IMAGE)"; cat "$work/err"; rc=1
	fi
done
exit $rc
