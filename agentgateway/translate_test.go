// SPDX-License-Identifier: Apache-2.0

package agentgateway

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

func TestGolden(t *testing.T) {
	for _, name := range []string{"basic", "hosts-only"} {
		t.Run(name, func(t *testing.T) {
			files, err := Translate(load(t, "testdata/"+name+".intent.json"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := files[ConfigFile]
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
				t.Errorf("%s differs from %s (go test ./agentgateway -update)", name, golden)
			}
		})
	}
}

// The parts that make it safe: the PROXY header is required, a host rule
// dials the name, an address rule the original destination only when a cidr
// matches, and anything else the loopback sentinel agentgateway refuses.
func TestShape(t *testing.T) {
	files, err := Translate(load(t, "testdata/basic.intent.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := string(files[ConfigFile])
	for _, want := range []string{
		`"mode": "strict"`,
		`"version": "v2"`,
		`"port": 15006`,
		`destination.port in [80, 443] ? destination.hostname + \":\" + string(destination.port) : \"127.0.0.1:9\"`,
		`destination.port in [443] ? destination.hostname`,
		`"allow": "destination.port in [80]"`,
		`(cidr(\"10.96.0.12/32\").containsIP(destination.address) && destination.port in [8080]) || cidr(\"203.0.113.0/24\").containsIP(destination.address)`,
		`"statsAddr": "off"`,
		`"adminAddr": "127.0.0.1:15000"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %s", want)
		}
	}
	h, err := Translate(load(t, "testdata/hosts-only.intent.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(h[ConfigFile]), `"name": "tcp"`) || strings.Contains(string(h[ConfigFile]), "destination.address +") {
		t.Errorf("no address rules, but the config reaches original destinations:\n%s", h[ConfigFile])
	}
}

func TestRefused(t *testing.T) {
	base := func() *v1.EgressIntent { return load(t, "testdata/basic.intent.json") }
	for name, mut := range map[string]func(*v1.EgressIntent){
		"no proxyProtocol":  func(in *v1.EgressIntent) { in.Listeners.ProxyProtocol = "" },
		"bad proxyProtocol": func(in *v1.EgressIntent) { in.Listeners.ProxyProtocol = "v3" },
		"dns listener":      func(in *v1.EgressIntent) { in.Listeners.DNS = 15053 },
		"http listener":     func(in *v1.EgressIntent) { in.Listeners.HTTP = 15080 },
		"credentials":       func(in *v1.EgressIntent) { in.Credentials = []v1.Credential{{}} },
		"tls origination":   func(in *v1.EgressIntent) { in.Allow[0].TLS = &v1.RuleTLS{Originate: "SPIFFE"} },
		"bad host":          func(in *v1.EgressIntent) { in.Allow[0].Host = `x") || true || ("` },
		"ipv6 cidr":         func(in *v1.EgressIntent) { in.Allow[2].CIDR = "2001:db8::/32" },
		"host and cidr":     func(in *v1.EgressIntent) { in.Allow[2].Host = "a.example" },
		"udp":               func(in *v1.EgressIntent) { in.Allow[2].Ports[0].Protocol = "UDP" },
	} {
		in := base()
		mut(in)
		if _, err := Translate(in, Options{}); err == nil {
			t.Errorf("%s: translated, want an error", name)
		}
	}
}
