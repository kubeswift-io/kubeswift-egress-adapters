# Changelog

## [Unreleased]

### Added

- SPIFFE TLS origination in the Envoy translator (`rule.tls`, KubeSwift's
  `allow[].tls`): the guest speaks plaintext and Envoy connects over TLS with
  the sandbox's X.509-SVID, read over SDS from the agent at
  `identity.spiffe.workloadAPISocket`, accepting only an upstream SVID of the
  sandbox's trust domain. Address rules use an `ORIGINAL_DST` cluster; host
  rules (which need ports) are served as plain HTTP and forwarded with SNI.
  `--spiffe-svid-name` / `--spiffe-bundle-name` (default SPIRE's `default` and
  `ROOTCA`).
- The image declares `io.kubeswift.egress-intent.features="tls-originate"`;
  KubeSwift requires it before writing `rule.tls`.

### Changed

- `intent/v1` pinned to kubeswift-io/kubeswift@42b7e8b8: `identity.spiffe.id`.

## [v0.2.0] - 2026-11-17

Credentials in the Envoy translator, for KubeSwift egress credentials.

### Added

- Credentials in the Envoy translator: an intercept chain per credential
  destination with the leaf certificate KubeSwift issued, the header set from
  the credential file (`credential_injector`), 403 for any other `Host`, TLS
  to the upstream verified against `--upstream-ca` (default the Envoy image's
  bundle). Certificates and values are read through SDS files that watch
  `secretsDir`, so KubeSwift's swap at a warm-slot claim reloads them; an
  empty value answers 401.
- `--admin-port`: Envoy's admin endpoint on 127.0.0.1, for a preset readiness
  probe on `/certs`.
- `hack/e2e-envoy-credentials.sh`, run in CI on Envoy v1.36 and v1.35.

### Changed

- Intent v1 schema copy updated: `secretsDir`, `tls.certificates`,
  `credentials[].headerValueFile`, optional `tls.interceptCA.key`.
- `envoy.Translate` takes `Options` and returns every output file;
  `hack/validate-envoy.sh` loads the translator's real output.

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
