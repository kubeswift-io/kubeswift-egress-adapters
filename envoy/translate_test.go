// SPDX-License-Identifier: Apache-2.0

package envoy

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"reflect"
	"regexp"
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

// goldenDir is the output directory the golden files are rendered for.
const goldenDir = "/etc/kubeswift/egress-proxy"

// render returns every output file in one JSON document, keyed by name.
func render(t *testing.T, in *v1.EgressIntent, opt Options) []byte {
	t.Helper()
	files, err := Translate(in, opt)
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]json.RawMessage{}
	for name, b := range files {
		all[name] = b
	}
	out, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The translation of each testdata intent matches its golden file
// (go test ./envoy -update rewrites them; hack/validate-envoy.sh loads the
// translator's real output in Envoy).
func TestGolden(t *testing.T) {
	for _, name := range []string{"basic", "cidr-any-port", "credentials", "http-listener", "spiffe"} {
		t.Run(name, func(t *testing.T) {
			got := render(t, load(t, "testdata/"+name+".intent.json"), Options{Dir: goldenDir, AdminPort: 15000})
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
	files, err := Translate(in, Options{Dir: goldenDir})
	if err != nil {
		t.Fatal(err)
	}
	b := files[BootstrapFile]
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
		"dns listener":          func() *v1.EgressIntent { i := intent(); i.Listeners.DNS = 15053; return i }(),
		"tls without identity":  intent(v1.Rule{CIDR: "10.0.0.1/32", TLS: &v1.RuleTLS{Originate: "SPIFFE"}, From: "x"}),
		"wrong version":         func() *v1.EgressIntent { i := intent(); i.APIVersion = "egress-intent.kubeswift.io/v2"; return i }(),
		"ipv6 cidr":             intent(v1.Rule{CIDR: "fd00::/8", From: "x"}),
		"http on transparent":   func() *v1.EgressIntent { i := intent(); i.Listeners.HTTP = i.Listeners.Transparent; return i }(),
		"http with credentials": credIntent(func(i *v1.EgressIntent) { i.Listeners.HTTP = 3128 }),
		"http with tls rule": func() *v1.EgressIntent {
			i := spiffeIntent(v1.Rule{CIDR: "10.0.0.1/32", TLS: &v1.RuleTLS{Originate: "SPIFFE"}, From: "x"})
			i.Listeners.HTTP = 3128
			return i
		}(),
	} {
		if _, err := Translate(in, Options{Dir: goldenDir}); err == nil {
			t.Errorf("%s: translated, want an error", name)
		}
	}
}

func credIntent(mut func(*v1.EgressIntent)) *v1.EgressIntent {
	in := intent(v1.Rule{Host: "api.example.com", Ports: tcp(443), From: "host api.example.com"})
	in.SecretsDir = "/run/kubeswift/egress/secrets"
	in.TLS = &v1.TLS{
		InterceptCA:  v1.CA{Cert: "/run/kubeswift/egress/secrets/ca.crt"},
		Certificates: []v1.Certificate{{Hosts: []string{"api.example.com"}, Cert: "/run/kubeswift/egress/secrets/cert-0.crt", Key: "/run/kubeswift/egress/secrets/cert-0.key"}},
	}
	in.Credentials = []v1.Credential{{
		Name: "API_KEY", Placeholder: "ks-0123456789abcdef", Destinations: []string{"api.example.com:443"},
		Header: "Authorization", ValueTemplate: "Bearer {}",
		File: "/run/kubeswift/egress/secrets/cred-API_KEY", HeaderValueFile: "/run/kubeswift/egress/secrets/header-API_KEY",
	}}
	if mut != nil {
		mut(in)
	}
	return in
}

// A credential destination gets an intercept chain, and the passthrough TLS
// chain no longer names the host (Envoy refuses two equal matches); with no
// other name left on the port the passthrough chain is gone (an empty
// server_names would match every name).
func TestCredentialIntercept(t *testing.T) {
	cs := chains(t, credIntent(nil))
	if _, ok := cs["intercept-api.example.com-443"]; !ok {
		t.Fatalf("no intercept chain: %v", cs)
	}
	if _, ok := cs["tls-443"]; ok {
		t.Errorf("tls-443 still present: %v", cs["tls-443"])
	}
	cs = chains(t, credIntent(func(in *v1.EgressIntent) {
		in.Allow = append(in.Allow, v1.Rule{Host: "other.example.com", Ports: tcp(443), From: "host other.example.com"})
	}))
	if names := cs["tls-443"]["server_names"]; !reflect.DeepEqual(names, []any{"other.example.com"}) {
		t.Errorf("tls-443 server_names = %v", names)
	}
}

func TestCredentialRefusals(t *testing.T) {
	for name, mut := range map[string]func(*v1.EgressIntent){
		"no certificates":   func(in *v1.EgressIntent) { in.TLS.Certificates = nil },
		"no secretsDir":     func(in *v1.EgressIntent) { in.SecretsDir = "" },
		"template, no file": func(in *v1.EgressIntent) { in.Credentials[0].HeaderValueFile = "" },
		"wildcard":          func(in *v1.EgressIntent) { in.Credentials[0].Destinations = []string{"*.example.com:443"} },
		"not allowed":       func(in *v1.EgressIntent) { in.Credentials[0].Destinations = []string{"api.example.com:8443"} },
		"no cert for host":  func(in *v1.EgressIntent) { in.TLS.Certificates[0].Hosts = []string{"x.example.com"} },
		"file outside dir":  func(in *v1.EgressIntent) { in.Credentials[0].HeaderValueFile = "/etc/passwd" },
		"same header twice": func(in *v1.EgressIntent) {
			c := in.Credentials[0]
			c.Name = "OTHER"
			in.Credentials = append(in.Credentials, c)
		},
	} {
		if _, err := Translate(credIntent(mut), Options{Dir: goldenDir}); err == nil {
			t.Errorf("%s: translated, want an error", name)
		}
	}
	// A bare "{}" template needs no rendered file.
	if _, err := Translate(credIntent(func(in *v1.EgressIntent) {
		in.Credentials[0].ValueTemplate = "{}"
		in.Credentials[0].HeaderValueFile = ""
	}), Options{Dir: goldenDir}); err != nil {
		t.Errorf("template {}: %v", err)
	}
}

func spiffeIntent(rules ...v1.Rule) *v1.EgressIntent {
	in := intent(rules...)
	in.Identity = &v1.Identity{SPIFFE: &v1.SPIFFE{
		WorkloadAPISocket: "unix:///run/spiffe/spire-agent.sock",
		ID:                "spiffe://kubeswift.test/ns/a/pool/p/slot/p-x",
	}}
	return in
}

// A cidr rule with tls gets its own chain to the SPIFFE ORIGINAL_DST
// cluster; a host rule with tls is served as plain HTTP and routed to the
// SPIFFE dynamic forward proxy. Both clusters present the SVID from SDS and
// accept only an upstream SVID of the trust domain.
func TestSPIFFEOrigination(t *testing.T) {
	tls := &v1.RuleTLS{Originate: "SPIFFE"}
	in := spiffeIntent(
		v1.Rule{CIDR: "10.96.0.12/32", Ports: tcp(8443), TLS: tls, From: "service ai/llm"},
		v1.Rule{CIDR: "10.96.0.13/32", Ports: tcp(8443), From: "service ai/plain"},
		v1.Rule{Host: "mcp.example.com", Ports: tcp(8080), TLS: tls, From: "host mcp.example.com"},
		v1.Rule{Host: "api.example.com", Ports: tcp(8080), From: "host api.example.com"},
	)
	files, err := Translate(in, Options{Dir: goldenDir})
	if err != nil {
		t.Fatal(err)
	}
	b := string(files[BootstrapFile])
	for _, want := range []string{
		`"name": "cidr-spiffe-8443"`, `"cluster": "original_dst_spiffe"`,
		`"cluster": "dynamic_forward_proxy_spiffe"`, `"prefix": "spiffe://kubeswift.test/"`,
		`"path": "/run/spiffe/spire-agent.sock"`, `"name": "default"`, `"name": "ROOTCA"`,
		`"id": "kubeswift-sandbox"`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("bootstrap lacks %s", want)
		}
	}
	cs := chains(t, in)
	if _, ok := cs["cidr-8443"]; !ok {
		t.Error("the plain cidr rule lost its chain")
	}
	// The vhost of the tls host routes to the SPIFFE cluster, the other one
	// to the plain forward proxy.
	var routes map[string]string
	var raw map[string]any
	if err := json.Unmarshal(files[BootstrapFile], &raw); err != nil {
		t.Fatal(err)
	}
	routes = map[string]string{}
	for _, fc := range raw["static_resources"].(map[string]any)["listeners"].([]any)[0].(map[string]any)["filter_chains"].([]any) {
		f := fc.(map[string]any)
		if f["name"] != "http-8080" {
			continue
		}
		hcm := f["filters"].([]any)[0].(map[string]any)["typed_config"].(map[string]any)
		for _, vh := range hcm["route_config"].(map[string]any)["virtual_hosts"].([]any) {
			v := vh.(map[string]any)
			r := v["routes"].([]any)[0].(map[string]any)
			if rt, ok := r["route"].(map[string]any); ok {
				routes[v["name"].(string)] = rt["cluster"].(string)
			}
		}
	}
	if routes["host-mcp.example.com"] != "dynamic_forward_proxy_spiffe" || routes["host-api.example.com"] != "dynamic_forward_proxy" {
		t.Errorf("routes %v", routes)
	}
	// No tls rule, no SPIFFE clusters even with an identity.
	files, err = Translate(spiffeIntent(v1.Rule{CIDR: "10.0.0.1/32", From: "x"}), Options{Dir: goldenDir})
	if err != nil || strings.Contains(string(files[BootstrapFile]), "spiffe") {
		t.Errorf("identity without tls rules: %v", err)
	}
}

func TestSPIFFERefusals(t *testing.T) {
	tls := &v1.RuleTLS{Originate: "SPIFFE"}
	for name, in := range map[string]*v1.EgressIntent{
		"host without ports": spiffeIntent(v1.Rule{Host: "mcp.example.com", TLS: tls, From: "x"}),
		"not SPIFFE":         spiffeIntent(v1.Rule{CIDR: "10.0.0.1/32", TLS: &v1.RuleTLS{Originate: "X509"}, From: "x"}),
		"same destination twice": spiffeIntent(
			v1.Rule{CIDR: "10.0.0.1/32", Ports: tcp(443), TLS: tls, From: "a"},
			v1.Rule{CIDR: "10.0.0.1/32", Ports: tcp(443), From: "b"}),
		"tcp socket": func() *v1.EgressIntent {
			i := spiffeIntent(v1.Rule{CIDR: "10.0.0.1/32", TLS: tls, From: "x"})
			i.Identity.SPIFFE.WorkloadAPISocket = "tcp://127.0.0.1:8081"
			return i
		}(),
		"no id": func() *v1.EgressIntent {
			i := spiffeIntent(v1.Rule{CIDR: "10.0.0.1/32", TLS: tls, From: "x"})
			i.Identity.SPIFFE.ID = ""
			return i
		}(),
	} {
		if _, err := Translate(in, Options{Dir: goldenDir}); err == nil {
			t.Errorf("%s: translated, want an error", name)
		}
	}
}

// The cidr expression matches the canonical dotted addresses inside the
// prefix on the rule's port, and nothing else.
func TestAuthorityRegex(t *testing.T) {
	for _, tc := range []struct {
		cidr  string
		port  int
		match []string
		miss  []string
	}{
		{"10.96.14.7/32", 8080, []string{"10.96.14.7:8080"}, []string{"10.96.14.7:80", "10.96.14.70:8080", "010.96.14.7:8080", "10.96.14.7"}},
		{"10.20.16.0/20", 0, []string{"10.20.16.0:1", "10.20.31.255:443", "10.20.20.5"}, []string{"10.20.32.1:443", "10.20.15.255:443", "10.20.16.256:1", "10.20.16.01:1", "example.com:443"}},
		{"192.168.1.0/24", 80, []string{"192.168.1.9", "192.168.1.9:80"}, []string{"192.168.1.9:8080", "192.168.2.9"}},
		{"0.0.0.0/0", 443, []string{"8.8.8.8:443", "255.255.255.255:443"}, []string{"8.8.8.8:80", "167772165:443", "0x7f.0.0.1:443", "a.example.com:443"}},
	} {
		re := regexp.MustCompile("^(?:" + *authorityRegex([]cidr{{prefix: netip.MustParsePrefix(tc.cidr)}}, tc.port) + ")$")
		for _, a := range tc.match {
			if !re.MatchString(a) {
				t.Errorf("%s port %d: %q not matched by %s", tc.cidr, tc.port, a, re)
			}
		}
		for _, a := range tc.miss {
			if re.MatchString(a) {
				t.Errorf("%s port %d: %q matched by %s", tc.cidr, tc.port, a, re)
			}
		}
	}
}
