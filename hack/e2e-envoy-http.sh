#!/usr/bin/env bash
# Behaviour of the explicit HTTP listener (listeners.http) with the real
# translator and an unmodified Envoy (docker, no cluster; the public checks
# need internet from the Envoy container). Run from the host, which reaches
# the containers on their docker network:
#   - CONNECT and absolute-URI requests reach an allowed name on its ports
#     (a host rule without ports: 443 and 80; a wildcard on 443 only);
#   - another name, another port, a name ending in a dot and a Host header
#     naming an allowed host on a request for another get 403;
#   - an IPv4 literal reaches a cidr rule's address on its port only, and
#     non-canonical spellings of that address (leading zeros, one decimal
#     number, hex) get 403;
#   - the rule's Service is reached by its names (app, app.e2e, app.e2e.svc,
#     app.e2e.svc.cluster.local) on its port only, connecting to the rule's
#     address with no DNS; another name or namespace gets 403.
set -euo pipefail
ENVOY_IMAGE="${ENVOY_IMAGE:-docker.io/envoyproxy/envoy:v1.36.2}"
PY_IMAGE="${PY_IMAGE:-docker.io/library/python:3.13-alpine}"
PUBLIC_HOST="${PUBLIC_HOST:-example.com}"
OTHER_HOST="${OTHER_HOST:-github.com}"
cd "$(dirname "$0")/.."
work=$(mktemp -d) net="egress-http-e2e-$$"
cleanup() { docker rm -f "$net-envoy" "$net-up" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail=0
go build -o "$work/egress-translator" ./cmd/egress-translator
docker network create "$net" >/dev/null
docker run -d --name "$net-up" --network "$net" "$PY_IMAGE" \
	sh -c 'python3 -m http.server 8080 & exec python3 -m http.server 8081' >/dev/null
up=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$net-up")
# The checks below need the upstream answering on both ports.
for port in 8080 8081; do
	for _ in $(seq 120); do curl -s -m 1 -o /dev/null "http://$up:$port/" && break; sleep 0.5; done
	curl -s -m 2 -o /dev/null "http://$up:$port/" || { echo "FAIL: upstream not answering on $port" >&2; exit 1; }
done
mkdir -p "$work/out"
cat > "$work/intent.json" <<EOF
{"apiVersion": "egress-intent.kubeswift.io/v1", "kind": "EgressIntent",
 "owner": {"namespace": "e2e", "kind": "SwiftSandbox", "name": "http"},
 "listeners": {"transparent": 15006, "http": 3128},
 "allow": [
  {"host": "$PUBLIC_HOST", "from": "host $PUBLIC_HOST"},
  {"host": "*.$PUBLIC_HOST", "ports": [{"port": 443, "protocol": "TCP"}], "from": "host *.$PUBLIC_HOST"},
  {"cidr": "$up/32", "ports": [{"port": 8080, "protocol": "TCP"}], "service": {"namespace": "e2e", "name": "app"}, "from": "service e2e/app"}
 ]}
EOF
"$work/egress-translator" envoy --intent "$work/intent.json" --out "$work/out/envoy.json" >/dev/null
chmod -R a+rX "$work"
docker run -d --name "$net-envoy" --network "$net" -v "$work/out:/cfg:ro" "$ENVOY_IMAGE" \
	-c /cfg/envoy.json --log-level warn >/dev/null
proxy=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$net-envoy")
for _ in $(seq 30); do curl -s -o /dev/null "http://$proxy:3128/" && break; sleep 1; done

res() { if [ "$2" = "$3" ]; then echo "ok   $1 $2"; else echo "FAIL $1 got $2, want $3"; fail=1; fi; }
# get NAME WANT CURL-ARGS: through the proxy (-p: CONNECT even for http://).
get() { local n=$1 w=$2 g=block; shift 2; curl -sSf -m 10 -o /dev/null -x "http://$proxy:3128" "$@" 2>/dev/null && g=reach; res "$n" $g "$w"; }
# raw NAME WANT AUTHORITY: a CONNECT request as written, unnormalized.
raw() { local g=block; printf 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' "$3" "$3" | timeout 5 nc "$proxy" 3128 | head -1 | grep -q ' 200 ' && g=reach; res "$1" $g "$2"; }

get https-allowed reach "https://$PUBLIC_HOST/"
get http-allowed reach "http://$PUBLIC_HOST/"
get https-wildcard reach "https://www.$PUBLIC_HOST/"
get http-wildcard-port-80 block "http://www.$PUBLIC_HOST/"
get https-other block "https://$OTHER_HOST/"
get http-other block "http://$OTHER_HOST/"
get connect-other-port block -p "https://$PUBLIC_HOST:8443/"
get http-other-port block "http://$PUBLIC_HOST:8080/"
get trailing-dot block "https://$PUBLIC_HOST./"
get host-header-spoof block -H "Host: $PUBLIC_HOST" "http://$OTHER_HOST/"
get cidr-forward reach "http://$up:8080/"
get cidr-connect reach -p "http://$up:8080/"
get cidr-other-port block "http://$up:8081/"
get cidr-other-port-connect block -p "http://$up:8081/"
o1=${up%%.*} rest=${up#*.}
raw raw-cidr reach "$up:8080"
raw raw-leading-zeros block "${up%.*}.$(printf %03d "${up##*.}"):8080"
raw raw-decimal block "$(IFS=. read -r a b c d <<<"$up"; echo $(( (a<<24) + (b<<16) + (c<<8) + d ))):8080"
raw raw-hex block "$(printf '0x%x' "$o1").$rest:8080"
raw raw-other-name block "$OTHER_HOST:443"
get service-name reach "http://app:8080/"
get service-name-ns reach "http://app.e2e:8080/"
get service-name-svc-connect reach -p "http://app.e2e.svc:8080/"
get service-fqdn-connect reach -p "http://app.e2e.svc.cluster.local:8080/"
get service-other-port block "http://app:8081/"
get service-other-namespace block "http://app.other:8080/"
get service-other-name block "http://db:8080/"
raw raw-service-name reach "app:8080"
if [ $fail != 0 ]; then docker logs "$net-envoy" 2>&1 | tail -20 >&2; exit 1; fi
echo "PASS: the HTTP listener allows only the allowlist, by name and canonical address"
