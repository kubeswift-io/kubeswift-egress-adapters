# Changelog

## [v0.1.0] - 2026-11-17

First release: the Envoy translator.

### Added

- `egress-translator envoy` turns an `egress-intent.kubeswift.io/v1` file into
  a static bootstrap for an unmodified Envoy (tested with v1.35 and v1.36).
  `cidr` rules forward to the original destination; `host` rules match the TLS
  server name or the HTTP `Host` header and forward to the address the name
  resolves to. A `host` rule without ports opens 443 (TLS) and 80 (HTTP).
  Refused with an error: a DNS listener, an explicit HTTP listener, TLS
  origination and credentials.
- Image `ghcr.io/kubeswift-io/kubeswift-egress-adapters/envoy-translator`
  with the label `io.kubeswift.egress-intent.versions=v1`, signed with cosign
  (keyless), with SBOM and SLSA provenance attached.
- Go types for intent v1, checked against the schema copied from KubeSwift
  (`intent/v1/SCHEMA_SOURCE`).

### Use

It needs KubeSwift with egress proxy presets (`spec.network.egress.proxy.preset`).
