// SPDX-License-Identifier: Apache-2.0

// Package agentgateway turns an egress-intent.kubeswift.io/v1 file into a
// static configuration for an unmodified agentgateway, the egress proxy of a
// proxied KubeSwift sandbox.
//
// agentgateway does not read SO_ORIGINAL_DST, so the intent must set
// listeners.proxyProtocol: KubeSwift then sends every guest connection
// through a relay that starts it with a PROXY protocol header carrying the
// original destination, and agentgateway requires that header (strict). One
// bind on the transparent port detects the protocol of each connection:
//
//   - TLS: a host rule matches the server name and connects to the name (not
//     the original destination) on the port the guest asked for, if the rule
//     allows that port. Address rules match a TLS connection whose server
//     name no host rule covers, by original destination.
//   - HTTP: a host rule matches the Host header and connects to the name; a
//     request no host rule matches goes to its original destination when an
//     address rule allows it, else it is refused.
//   - Anything else: address rules, by original destination.
//
// A host rule without ports allows TLS on 443 and HTTP on 80. A destination
// nothing allows resolves to the loopback sentinel, which agentgateway
// refuses to dial, so the connection fails closed.
//
// Not supported, refused with an error: an intent without proxyProtocol,
// DNS and HTTP listeners, credentials and TLS origination (rule.tls).
package agentgateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/kubeswift-io/kubeswift-egress-adapters/intent/v1"
)

// ConfigFile is the name of the configuration in the output.
const ConfigFile = "agentgateway.json"

// Options are what the intent does not say.
type Options struct {
	// AdminPort is agentgateway's admin endpoint on 127.0.0.1 (default 15000).
	AdminPort int
	// ReadinessPort is its readiness endpoint on 127.0.0.1 (default 15021).
	ReadinessPort int
}

// deny is a dynamic backend agentgateway refuses (allowDynamicLoopback is
// off by default), so a connection resolved to it is closed.
const deny = `"127.0.0.1:9"`

type obj = map[string]any

// Translate returns the files to write: ConfigFile.
func Translate(in *v1.EgressIntent, opt Options) (map[string][]byte, error) {
	if err := supported(in); err != nil {
		return nil, err
	}
	if opt.AdminPort == 0 {
		opt.AdminPort = 15000
	}
	if opt.ReadinessPort == 0 {
		opt.ReadinessPort = 15021
	}

	var hosts []v1.Rule
	var cidrs []v1.Rule
	for _, r := range in.Allow {
		switch {
		case r.Host != "" && r.CIDR == "":
			if !validHost(r.Host) {
				return nil, fmt.Errorf("allow %q: host %q is not a DNS name or *.name", r.From, r.Host)
			}
			hosts = append(hosts, r)
		case r.CIDR != "" && r.Host == "":
			if _, n, err := net.ParseCIDR(r.CIDR); err != nil || n.IP.To4() == nil {
				return nil, fmt.Errorf("allow %q: cidr %q is not an IPv4 range", r.From, r.CIDR)
			}
			cidrs = append(cidrs, r)
		default:
			return nil, fmt.Errorf("allow %q: set exactly one of host and cidr", r.From)
		}
		for _, p := range r.Ports {
			if p.Protocol != "" && p.Protocol != "TCP" {
				return nil, fmt.Errorf("allow %q: protocol %s: only TCP is supported", r.From, p.Protocol)
			}
			if p.Port < 1 || p.Port > 65535 {
				return nil, fmt.Errorf("allow %q: port %d out of range", r.From, p.Port)
			}
		}
	}

	addr := cidrExpr(cidrs) // "" when there are no address rules
	toOriginal := func(cond string) obj {
		return obj{"dynamic": obj{"target": cond + ` ? destination.address + ":" + string(destination.port) : ` + deny}}
	}

	var listeners []obj
	// TLS: by server name, then by address.
	var tlsRoutes []obj
	for i, r := range hosts {
		tlsRoutes = append(tlsRoutes, obj{
			"name":      fmt.Sprintf("host-%d", i),
			"hostnames": []string{r.Host},
			"backends": []obj{{"dynamic": obj{"target": portExpr(r, 443) +
				` ? destination.hostname + ":" + string(destination.port) : ` + deny}}},
		})
	}
	if addr != "" {
		tlsRoutes = append(tlsRoutes, obj{"name": "address", "backends": []obj{toOriginal(addr)}})
	}
	if len(tlsRoutes) > 0 {
		listeners = append(listeners, obj{"name": "tls", "protocol": "TLS", "hostname": "*", "tcpRoutes": tlsRoutes})
	}
	// HTTP: by Host, then by address.
	var httpRoutes []obj
	for i, r := range hosts {
		httpRoutes = append(httpRoutes, obj{
			"name":      fmt.Sprintf("host-%d", i),
			"hostnames": []string{r.Host},
			"policies":  obj{"authorization": obj{"rules": []obj{{"allow": portExpr(r, 80)}}}},
			"backends":  []obj{{"dynamic": obj{"target": `request.host + ":" + string(destination.port)`}}},
		})
	}
	if addr != "" {
		httpRoutes = append(httpRoutes, obj{
			"name":     "address",
			"matches":  []obj{{"path": obj{"pathPrefix": "/"}}},
			"policies": obj{"authorization": obj{"rules": []obj{{"allow": addr}}}},
			"backends": []obj{{"dynamic": obj{"target": `destination.address + ":" + string(destination.port)`}}},
		})
	}
	if len(httpRoutes) > 0 {
		listeners = append(listeners, obj{"name": "http", "protocol": "HTTP", "routes": httpRoutes})
	}
	// Anything else: by address.
	if addr != "" {
		listeners = append(listeners, obj{"name": "tcp", "protocol": "TCP",
			"tcpRoutes": []obj{{"name": "address", "backends": []obj{toOriginal(addr)}}}})
	}

	cfg := obj{
		"config": obj{
			"adminAddr":     "127.0.0.1:" + strconv.Itoa(opt.AdminPort),
			"readinessAddr": "127.0.0.1:" + strconv.Itoa(opt.ReadinessPort),
			"statsAddr":     "off",
			"session":       obj{"key": "disabled"},
		},
		"frontendPolicies": obj{"proxyProtocol": obj{"version": in.Listeners.ProxyProtocol, "mode": "strict"}},
		"binds": []obj{{
			"port":      in.Listeners.Transparent,
			"protocol":  "AUTO",
			"listeners": listeners,
		}},
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false) // keep && readable in the CEL
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return nil, err
	}
	return map[string][]byte{ConfigFile: bytes.TrimRight(b.Bytes(), "\n")}, nil
}

func supported(in *v1.EgressIntent) error {
	l := in.Listeners
	switch {
	case l.Transparent < 1 || l.Transparent > 65535:
		return fmt.Errorf("listeners.transparent %d out of range", l.Transparent)
	case l.ProxyProtocol != "v1" && l.ProxyProtocol != "v2":
		return fmt.Errorf("listeners.proxyProtocol %q: agentgateway cannot read SO_ORIGINAL_DST; the preset must set proxyProtocol v1 or v2", l.ProxyProtocol)
	case l.DNS != 0:
		return fmt.Errorf("listeners.dns is not supported by the agentgateway translator")
	case l.HTTP != 0:
		return fmt.Errorf("listeners.http is not supported by the agentgateway translator")
	case len(in.Credentials) > 0:
		return fmt.Errorf("credentials are not supported by the agentgateway translator")
	}
	for _, r := range in.Allow {
		if r.TLS != nil {
			return fmt.Errorf("allow %q: tls origination is not supported by the agentgateway translator", r.From)
		}
	}
	return nil
}

// portExpr is the CEL condition for a host rule's ports; a rule without
// ports allows def only.
func portExpr(r v1.Rule, def int32) string {
	ports := []int32{def}
	if len(r.Ports) > 0 {
		ports = ports[:0]
		for _, p := range r.Ports {
			ports = append(ports, p.Port)
		}
	}
	return "destination.port in " + list(ports)
}

// cidrExpr is the CEL condition matching an original destination any
// address rule allows, or "".
func cidrExpr(rules []v1.Rule) string {
	var terms []string
	for _, r := range rules {
		t := fmt.Sprintf("cidr(%q).containsIP(destination.address)", r.CIDR)
		if len(r.Ports) > 0 {
			var ports []int32
			for _, p := range r.Ports {
				ports = append(ports, p.Port)
			}
			t = "(" + t + " && destination.port in " + list(ports) + ")"
		}
		terms = append(terms, t)
	}
	sort.Strings(terms)
	return strings.Join(dedupe(terms), " || ")
}

func list(ports []int32) string {
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	s := make([]string, 0, len(ports))
	for i, p := range ports {
		if i > 0 && p == ports[i-1] {
			continue
		}
		s = append(s, strconv.Itoa(int(p)))
	}
	return "[" + strings.Join(s, ", ") + "]"
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// validHost accepts a DNS name, optionally with a leading "*.", so nothing
// the guest controls ends up in a CEL expression or a hostname match.
func validHost(h string) bool {
	h = strings.TrimPrefix(h, "*.")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
