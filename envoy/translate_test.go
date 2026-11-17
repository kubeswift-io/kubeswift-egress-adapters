// SPDX-License-Identifier: Apache-2.0

package envoy

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	v1 "github.com/kubeswift-io/kubeswift-egress-adapters/intent/v1"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func load(t *testing.T, path string) *v1.EgressIntent {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in v1.EgressIntent
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	return &in
}

// The translation of each testdata intent matches its golden file
// (go test ./envoy -update rewrites them; hack/validate-envoy.sh checks them
// with a real Envoy).
func TestGolden(t *testing.T) {
	for _, name := range []string{"basic", "cidr-any-port"} {
		t.Run(name, func(t *testing.T) {
			got, err := Translate(load(t, "testdata/"+name+".intent.json"))
			if err != nil {
				t.Fatal(err)
			}
			golden := "testdata/" + name + ".golden.json"
			if *update {
				if err := os.WriteFile(golden, append(got, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(want)) != strings.TrimSpace(string(got)) {
				t.Errorf("%s differs from %s (go test ./envoy -update)", name, golden)
			}
		})
	}
}

type chain struct {
	Name  string         `json:"name"`
	Match map[string]any `json:"filter_chain_match"`
}

func chains(t *testing.T, in *v1.EgressIntent) map[string]map[string]any {
	t.Helper()
	b, err := Translate(in)
	if err != nil {
		t.Fatal(err)
	}
	var bs struct {
		StaticResources struct {
			Listeners []struct {
				FilterChains []chain `json:"filter_chains"`
			} `json:"listeners"`
		} `json:"static_resources"`
	}
	if err := json.Unmarshal(b, &bs); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, c := range bs.StaticResources.Listeners[0].FilterChains {
		if _, dup := out[c.Name]; dup {
			t.Fatalf("two chains named %s", c.Name)
		}
		out[c.Name] = c.Match
	}
	return out
}

func intent(rules ...v1.Rule) *v1.EgressIntent {
	return &v1.EgressIntent{APIVersion: v1.APIVersion, Kind: v1.Kind, Listeners: v1.Listeners{Transparent: 15006}, Allow: rules}
}

func tcp(ports ...int32) []v1.Port {
	var out []v1.Port
	for _, p := range ports {
		out = append(out, v1.Port{Port: p, Protocol: "TCP"})
	}
	return out
}

// A cidr rule for every port is repeated on every port another rule names:
// Envoy would otherwise send a 443 connection to that cidr to the TLS chain.
func TestCIDRAnyPortRepeatedOnNamedPorts(t *testing.T) {
	cs := chains(t, intent(
		v1.Rule{CIDR: "10.96.0.12/32", From: "service ai/llm"},
		v1.Rule{Host: "api.example.com", Ports: tcp(443), From: "host api.example.com"},
	))
	for _, name := range []string{"cidr-any", "cidr-443", "tls-443", "http-443"} {
		if _, ok := cs[name]; !ok {
			t.Errorf("no chain %s; have %v", name, cs)
		}
	}
}

// A host rule without ports opens TLS on 443 and HTTP on 80 only.
func TestHostWithoutPorts(t *testing.T) {
	cs := chains(t, intent(v1.Rule{Host: "*.example.com", From: "host *.example.com"}))
	if _, ok := cs["tls-443"]; !ok {
		t.Error("no tls-443")
	}
	if _, ok := cs["http-80"]; !ok {
		t.Error("no http-80")
	}
	if len(cs) != 2 {
		t.Errorf("chains %v", cs)
	}
}

// What the translator cannot honour fails loudly instead of being dropped.
func TestRefusals(t *testing.T) {
	for name, in := range map[string]*v1.EgressIntent{
		"dns listener":    func() *v1.EgressIntent { i := intent(); i.Listeners.DNS = 15053; return i }(),
		"credentials":     func() *v1.EgressIntent { i := intent(); i.Credentials = []v1.Credential{{Name: "K"}}; return i }(),
		"tls origination": intent(v1.Rule{CIDR: "10.0.0.1/32", TLS: &v1.RuleTLS{Originate: "SPIFFE"}, From: "x"}),
		"wrong version":   func() *v1.EgressIntent { i := intent(); i.APIVersion = "egress-intent.kubeswift.io/v2"; return i }(),
		"ipv6 cidr":       intent(v1.Rule{CIDR: "fd00::/8", From: "x"}),
	} {
		if _, err := Translate(in); err == nil {
			t.Errorf("%s: translated, want an error", name)
		}
	}
}
