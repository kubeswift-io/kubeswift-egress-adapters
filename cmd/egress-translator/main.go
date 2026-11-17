// SPDX-License-Identifier: Apache-2.0

// egress-translator turns the egress-intent.kubeswift.io/v1 file KubeSwift
// mounts into a proxy's own configuration. It runs once, as an init
// container next to an unmodified proxy image, and writes the configuration
// into a volume the proxy reads.
//
//	egress-translator envoy [--intent PATH] --out PATH [--admin-port N] [--upstream-ca PATH]
//	egress-translator agentgateway [--intent PATH] --out PATH [--admin-port N]
//
// --out names the bootstrap; SDS files for credentials are written next to
// it. --admin-port opens Envoy's admin endpoint on 127.0.0.1 (a preset's
// readiness probe reads /certs there).
//
// --intent defaults to $KUBESWIFT_EGRESS_INTENT, then
// /etc/kubeswift/egress/intent.json. Unknown intent fields are ignored, as
// the contract requires.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/kubeswift-io/kubeswift-egress-adapters/agentgateway"
	"github.com/kubeswift-io/kubeswift-egress-adapters/envoy"
	v1 "github.com/kubeswift-io/kubeswift-egress-adapters/intent/v1"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "egress-translator:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "agentgateway" {
		return runAgentgateway(args[1:])
	}
	if len(args) == 0 || args[0] != "envoy" {
		return fmt.Errorf("usage: egress-translator envoy|agentgateway [--intent PATH] --out PATH")
	}
	fs := flag.NewFlagSet("envoy", flag.ContinueOnError)
	intentPath := fs.String("intent", defaultIntent(), "egress-intent file")
	out := fs.String("out", "", "where to write the Envoy bootstrap; SDS files go next to it")
	admin := fs.Int("admin-port", 0, "open Envoy's admin endpoint on 127.0.0.1:N")
	upstreamCA := fs.String("upstream-ca", "", "CA bundle for intercepted upstreams (default the Envoy image's)")
	svidName := fs.String("spiffe-svid-name", "", `SDS name of the sandbox's SVID at the SPIFFE agent (default "default", SPIRE's)`)
	bundleName := fs.String("spiffe-bundle-name", "", `SDS name of the trust domain's bundle at the SPIFFE agent (default "ROOTCA", SPIRE's)`)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	in, err := readIntent(*intentPath)
	if err != nil {
		return err
	}
	dir, err := filepath.Abs(filepath.Dir(*out))
	if err != nil {
		return err
	}
	files, err := envoy.Translate(in, envoy.Options{Dir: dir, AdminPort: *admin, UpstreamCA: *upstreamCA, SVIDName: *svidName, BundleName: *bundleName})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	// SDS files first, bootstrap last; each written whole, then renamed, so
	// the proxy never reads a partial file.
	for _, name := range names {
		if name == envoy.BootstrapFile {
			continue
		}
		if err := write(filepath.Join(dir, name), files[name]); err != nil {
			return err
		}
	}
	if err := write(filepath.Join(dir, filepath.Base(*out)), files[envoy.BootstrapFile]); err != nil {
		return err
	}
	fmt.Printf("egress-translator: %s (%d allow rules, %d credentials) -> %s\n", *intentPath, len(in.Allow), len(in.Credentials), *out)
	return nil
}

func defaultIntent() string {
	if p := os.Getenv("KUBESWIFT_EGRESS_INTENT"); p != "" {
		return p
	}
	return v1.Path
}

func readIntent(path string) (*v1.EgressIntent, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in v1.EgressIntent
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &in, nil
}

func runAgentgateway(args []string) error {
	fs := flag.NewFlagSet("agentgateway", flag.ContinueOnError)
	intentPath := fs.String("intent", defaultIntent(), "egress-intent file")
	out := fs.String("out", "", "where to write the agentgateway configuration (JSON)")
	admin := fs.Int("admin-port", 0, "agentgateway's admin endpoint on 127.0.0.1:N (default 15000)")
	ready := fs.Int("readiness-port", 0, "agentgateway's readiness endpoint on 127.0.0.1:N (default 15021)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	in, err := readIntent(*intentPath)
	if err != nil {
		return err
	}
	files, err := agentgateway.Translate(in, agentgateway.Options{AdminPort: *admin, ReadinessPort: *ready})
	if err != nil {
		return err
	}
	if err := write(*out, files[agentgateway.ConfigFile]); err != nil {
		return err
	}
	fmt.Printf("egress-translator: %s (%d allow rules) -> %s\n", *intentPath, len(in.Allow), *out)
	return nil
}

func write(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
