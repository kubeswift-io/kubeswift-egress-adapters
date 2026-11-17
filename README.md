# kubeswift-egress-adapters

Translators that let unmodified egress proxies enforce a
[KubeSwift](https://github.com/kubeswift-io/kubeswift) sandbox's egress policy.

A KubeSwift sandbox in network mode `proxied` sends every guest TCP connection
to an egress proxy in its launcher pod. With `config: Intent`, KubeSwift mounts
a product-neutral policy file, `egress-intent.kubeswift.io/v1`, into the proxy.
A translator from this repository reads that file once, as an init container,
and writes the proxy's own configuration. The proxy image itself is the
upstream one, unchanged.

| Translator | Proxy | Status |
|---|---|---|
| `envoy` | [Envoy](https://www.envoyproxy.io/) | first version |
| `agentgateway` | [agentgateway](https://agentgateway.dev/) | planned |
| `openshell` | OpenShell supervisor | planned |

## Envoy

`egress-translator envoy --out /config/envoy.json` reads the intent file
(`$KUBESWIFT_EGRESS_INTENT`, else `/etc/kubeswift/egress/intent.json`) and
writes a static Envoy bootstrap with one transparent listener (plus, with
credentials, an SDS file per certificate and credential next to it):

- `cidr` rules (Services arrive resolved to `cidr` rules) forward to the
  connection's original destination.
- `host` rules match the TLS server name, or the `Host` header for plain HTTP,
  and forward to the address the name resolves to, never to the original
  destination, so a spoofed server name cannot reach another address.
- A `host` rule without ports opens TLS on 443 and HTTP on 80.
- A credential destination (`host:port`) is intercepted: Envoy terminates the
  guest's TLS with the leaf certificate KubeSwift issued for the host, sets the
  credential's header from its file (`credential_injector`), answers 403 to any
  other `Host` and forwards over TLS, verified against the Envoy image's CA
  bundle (`--upstream-ca`), to the name's address. An empty value answers 401.
  Certificates and values reload when KubeSwift swaps `secretsDir`.
- Anything else is closed. Every connection is logged on stdout.

`--admin-port N` opens Envoy's admin endpoint on 127.0.0.1; its `/certs` page
lists the serial numbers of the certificates Envoy serves, which a KubeSwift
preset's readiness probe checks after a swap.

Not supported yet, refused with an error: a DNS listener, an explicit HTTP
listener, TLS origination and wildcard credential destinations.

The image is `ghcr.io/kubeswift-io/kubeswift-egress-adapters/envoy-translator`
and carries the label `io.kubeswift.egress-intent.versions=v1`.
Release images are signed with cosign (keyless):

```bash
cosign verify ghcr.io/kubeswift-io/kubeswift-egress-adapters/envoy-translator:v0.1.0 \
  --certificate-identity-regexp '^https://github\.com/kubeswift-io/kubeswift-egress-adapters/\.github/workflows/release\.yaml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## The intent format

The contract is the JSON Schema published by KubeSwift
(`api/egressintent/v1` in kubeswift-io/kubeswift). `intent/v1/` holds a copy
pinned to a KubeSwift commit (`intent/v1/SCHEMA_SOURCE`) and Go types checked
against it. Readers ignore fields they do not know; a change they must not
ignore is a new version.

## Development

```bash
go test ./...                 # unit and golden tests
go test ./envoy -update       # rewrite envoy/testdata/*.golden.json
./hack/validate-envoy.sh      # load the translator's output in a real Envoy (docker)
./hack/e2e-envoy-credentials.sh   # credential path end to end (docker)
docker build -f images/envoy-translator/Containerfile .
```

## License

[Apache License, Version 2.0](LICENSE).
