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
writes a static Envoy bootstrap with one transparent listener:

- `cidr` rules (Services arrive resolved to `cidr` rules) forward to the
  connection's original destination.
- `host` rules match the TLS server name, or the `Host` header for plain HTTP,
  and forward to the address the name resolves to, never to the original
  destination, so a spoofed server name cannot reach another address.
- A `host` rule without ports opens TLS on 443 and HTTP on 80.
- Anything else is closed. Every connection is logged on stdout.

Not supported yet, refused with an error: a DNS listener, an explicit HTTP
listener, TLS origination and credentials.

The image is `ghcr.io/kubeswift-io/kubeswift-egress-adapters/envoy-translator`
and carries the label `io.kubeswift.egress-intent.versions=v1`.

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
./hack/validate-envoy.sh      # load every golden file in a real Envoy (docker)
docker build -f images/envoy-translator/Containerfile .
```

## License

[Apache License, Version 2.0](LICENSE).
