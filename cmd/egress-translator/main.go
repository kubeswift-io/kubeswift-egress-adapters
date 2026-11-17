// SPDX-License-Identifier: Apache-2.0

// egress-translator turns the egress-intent.kubeswift.io/v1 file KubeSwift
// mounts into a proxy's own configuration. It runs once, as an init
// container next to an unmodified proxy image, and writes the configuration
// into a volume the proxy reads.
//
//	egress-translator envoy [--intent PATH] --out PATH
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
	if len(args) == 0 || args[0] != "envoy" {
		return fmt.Errorf("usage: egress-translator envoy [--intent PATH] --out PATH")
	}
	fs := flag.NewFlagSet("envoy", flag.ContinueOnError)
	def := os.Getenv("KUBESWIFT_EGRESS_INTENT")
	if def == "" {
		def = v1.Path
	}
	intentPath := fs.String("intent", def, "egress-intent file")
	out := fs.String("out", "", "where to write the proxy configuration")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}
	raw, err := os.ReadFile(*intentPath)
	if err != nil {
		return err
	}
	var in v1.EgressIntent
	if err := json.Unmarshal(raw, &in); err != nil {
		return fmt.Errorf("%s: %w", *intentPath, err)
	}
	cfg, err := envoy.Translate(&in)
	if err != nil {
		return err
	}
	// Written whole, then renamed: the proxy never reads a partial file.
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".envoy-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(cfg, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), *out); err != nil {
		return err
	}
	fmt.Printf("egress-translator: %s (%d allow rules) -> %s\n", *intentPath, len(in.Allow), *out)
	return nil
}
