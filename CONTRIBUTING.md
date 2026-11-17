# Contributing

Issues and pull requests are welcome. For a new translator, or a change in how
an intent field is translated, open an issue first.

- **Sign off every commit** (`git commit -s`): the `Signed-off-by` line
  certifies, under the [Developer Certificate of Origin](https://developercertificate.org/),
  that you have the right to submit the work under this project's licence.
- Keep pull requests focused, and add tests: a golden file under
  `<translator>/testdata/` for each new case, and for a refusal a test that
  shows it is refused.
- `gofmt`, `go vet ./...`, `go test ./...` and `./hack/validate-envoy.sh` must
  pass. A translation that a real proxy would reject is a bug here.
- Translators never fork or patch the proxy: they write configuration for the
  upstream image.
- Pull requests are squash-merged, so write the title and description as the
  commit message.

Security issues: report them privately through GitHub's private vulnerability
reporting, not in public issues.

## Licence

Apache License, Version 2.0. By contributing, you agree that your
contributions are licensed under the same terms. Do not add code under a
licence that is not compatible with Apache-2.0 (no GPL or AGPL code).

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md).
