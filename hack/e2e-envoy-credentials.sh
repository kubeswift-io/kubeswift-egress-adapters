#!/usr/bin/env bash
# Behaviour of the credential path with the real translator and an unmodified
# Envoy (docker, no cluster):
#   - a placeholder in Authorization reaches the upstream as the real value;
#   - a Host other than the destination gets 403, never the credential;
#   - an empty value (a warm slot before its claim) gets 401;
#   - swapping secretsDir (new CA, leaf and value, the kubelet ..data layout)
#     is picked up without a restart: the new CA verifies, the old one fails,
#     the new value is injected and /certs lists the new serial.
# The destination port is the transparent listener's own port, so a direct
# connection matches the chain without an iptables redirect.
set -euo pipefail
ENVOY_IMAGE="${ENVOY_IMAGE:-docker.io/envoyproxy/envoy:v1.36.2}"
PY_IMAGE="${PY_IMAGE:-docker.io/library/python:3.13-alpine}"
cd "$(dirname "$0")/.."
work=$(mktemp -d) net="egress-e2e-$$"
cleanup() { docker rm -f "$net-envoy" "$net-up" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; docker logs "$net-envoy" 2>&1 | tail -20 >&2; exit 1; }
go build -o "$work/egress-translator" ./cmd/egress-translator
mkdir -p "$work/out" "$work/secrets" "$work/pki" "$work/up"

ca() { # ca NAME: a CA name-constrained to api.test
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=$1" \
		-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
		-addext "nameConstraints=critical,permitted;DNS:api.test" \
		-keyout "$work/pki/$1.key" -out "$work/pki/$1.crt" 2>/dev/null
}
leaf() { # leaf CA NAME
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=api.test \
		-keyout "$work/pki/$2.key" -out "$work/pki/$2.csr" 2>/dev/null
	printf 'subjectAltName=DNS:api.test\nextendedKeyUsage=serverAuth\n' > "$work/pki/ext"
	openssl x509 -req -in "$work/pki/$2.csr" -CA "$work/pki/$1.crt" -CAkey "$work/pki/$1.key" -CAcreateserial \
		-days 1 -extfile "$work/pki/ext" -out "$work/pki/$2.crt" 2>/dev/null
}
swap() { # swap CA LEAF VALUE: replace secretsDir content as KubeSwift does
	local d="$work/secrets" v="..v$RANDOM$RANDOM"
	mkdir "$d/$v"
	cp "$work/pki/$1.crt" "$d/$v/ca.crt"; cp "$work/pki/$2.crt" "$d/$v/cert-0.crt"; cp "$work/pki/$2.key" "$d/$v/cert-0.key"
	printf '%s' "$3" > "$d/$v/cred-API_KEY"; printf '%s' "${3:+Bearer $3}" > "$d/$v/header-API_KEY"
	chmod 755 "$d/$v"; chmod 444 "$d/$v"/*
	ln -s "$v" "$d/..tmp" && mv -T "$d/..tmp" "$d/..data"
	for f in ca.crt cert-0.crt cert-0.key cred-API_KEY header-API_KEY; do [ -L "$d/$f" ] || ln -s "..data/$f" "$d/$f"; done
}
ca ca1; leaf ca1 leaf1; ca ca2; leaf ca2 leaf2
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=api.test \
	-addext subjectAltName=DNS:api.test -keyout "$work/up/up.key" -out "$work/up/up.crt" 2>/dev/null
cat > "$work/up/up.py" <<'PY'
import http.server, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = ("auth=%s host=%s\n" % (self.headers.get("Authorization"), self.headers.get("Host"))).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("0.0.0.0", 15006), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/up/up.crt", "/up/up.key")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
cat > "$work/intent.json" <<'J'
{"apiVersion": "egress-intent.kubeswift.io/v1", "kind": "EgressIntent",
 "owner": {"namespace": "t", "kind": "SwiftSandbox", "name": "e2e"},
 "listeners": {"transparent": 15006},
 "allow": [{"host": "api.test", "ports": [{"port": 15006, "protocol": "TCP"}], "from": "host api.test"}],
 "credentials": [{"name": "API_KEY", "placeholder": "ks-placeholder-0123456789", "destinations": ["api.test:15006"],
   "header": "Authorization", "valueTemplate": "Bearer {}",
   "file": "/secrets/cred-API_KEY", "headerValueFile": "/secrets/header-API_KEY"}],
 "tls": {"interceptCA": {"cert": "/secrets/ca.crt"},
   "certificates": [{"hosts": ["api.test"], "cert": "/secrets/cert-0.crt", "key": "/secrets/cert-0.key"}]},
 "secretsDir": "/secrets"}
J
"$work/egress-translator" envoy --intent "$work/intent.json" --out "$work/out/envoy.json" --admin-port 15000 --upstream-ca /up/up.crt >/dev/null
sed -i "s#$work/out#/cfg#g" "$work/out"/*.json
swap ca1 leaf1 ""   # a warm slot: throwaway material, empty value
chmod -R a+rX "$work"

docker network create "$net" >/dev/null
docker run -d --name "$net-up" --network "$net" -v "$work/up:/up:ro" "$PY_IMAGE" python /up/up.py >/dev/null
sleep 2
up_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$net-up")
docker run -d --name "$net-envoy" --network "$net" --user 65531 --add-host "api.test:$up_ip" \
	-v "$work/out:/cfg:ro" -v "$work/secrets:/secrets:ro" -v "$work/up:/up:ro" \
	"$ENVOY_IMAGE" -c /cfg/envoy.json --disable-hot-restart --log-level warn >/dev/null
sleep 3

# The client runs in Envoy's network namespace (loopback), as the guest's
# redirected connection would arrive.
client() { docker run --rm --network "container:$net-envoy" -v "$work/pki:/pki:ro" "$PY_IMAGE" python -c "$1"; }
req() { # req CA [HOST]: status and body of GET https://api.test:15006/ via Envoy
	client "
import socket, ssl, sys
try:
    s = ssl.create_default_context(cafile='/pki/$1.crt').wrap_socket(socket.create_connection(('127.0.0.1', 15006), 8), server_hostname='api.test')
except Exception as e:
    print('tls-error'); sys.exit(0)
host = '${2:-api.test:15006}'
s.sendall(('GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer ks-placeholder-0123456789\r\nConnection: close\r\n\r\n' % host).encode())
d = b''
while True:
    b = s.recv(4096)
    if not b: break
    d += b
st = d.split(b' ')[1].decode(); body = d.split(b'\r\n\r\n', 1)[1].decode().strip()
print(st, body)
"
}
certs() { client "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:15000/certs').read().decode())"; }
serial() { openssl x509 -in "$work/pki/$1.crt" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f'; }

out=$(req ca1); echo "empty value:     $out"; [[ $out == 401* ]] || fail "empty value: want 401, got $out"
swap ca2 leaf2 "real-two"; sleep 1
out=$(req ca2); echo "after swap:      $out"; [[ $out == "200 auth=Bearer real-two host=api.test:15006" ]] || fail "want the real value, got $out"
out=$(req ca1); echo "old CA:          $out"; [ "$out" = tls-error ] || fail "old CA still verifies: $out"
out=$(req ca2 evil.test); echo "other Host:      $out"; [[ $out == 403* ]] || fail "other Host: want 403, got $out"
certs | grep -q "\"$(serial leaf2)\"" || fail "/certs does not list the new leaf serial"
echo "/certs lists the new leaf serial"
swap ca1 leaf1 "real-three"; sleep 1
out=$(req ca1); echo "second swap:     $out"; [[ $out == "200 auth=Bearer real-three host=api.test:15006" ]] || fail "second swap: got $out"
echo "PASS ($ENVOY_IMAGE)"
