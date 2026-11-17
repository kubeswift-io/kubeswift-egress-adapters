// SPDX-License-Identifier: Apache-2.0

// Package envoy turns an egress-intent.kubeswift.io/v1 file into a static
// Envoy bootstrap for the transparent listener of a proxied sandbox.
//
// The listener restores the original destination (original_dst), then picks
// a filter chain:
//
//   - cidr rules (and services, which KubeSwift resolves to cidr rules) match
//     the original destination address and port, and forward to it
//     (tcp_proxy to an ORIGINAL_DST cluster);
//   - host rules match the TLS server name (tls_inspector) or, for plain
//     HTTP, the Host header (http_inspector + a route per host), and forward
//     to the address the NAME resolves to (dynamic forward proxy), never to
//     the original destination. A spoofed server name therefore cannot reach
//     another address.
//
// A connection that matches no chain is closed.
//
// Envoy matches the destination port before anything else, and a chain that
// names no port is used for a port only when no chain names it. So a cidr
// rule for every port is repeated for each port another rule names, or a
// host rule on 443 would hide it.
//
// Not supported, refused with an error: a DNS or HTTP listener, TLS
// origination (rule.tls) and credentials.
package envoy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	v1 "github.com/kubeswift-io/kubeswift-egress-adapters/intent/v1"
)

const (
	originalDstCluster = "original_dst"
	dfpCluster         = "dynamic_forward_proxy"
	dnsCacheName       = "egress_dns_cache"
	// Ports a host rule without ports is opened on: TLS on 443, HTTP on 80.
	defaultTLSPort  = 443
	defaultHTTPPort = 80
)

type obj = map[string]any

func typed(t string, fields obj) obj {
	out := obj{"@type": "type.googleapis.com/" + t}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

var dnsCache = obj{"name": dnsCacheName, "dns_lookup_family": "V4_ONLY"}

var stdoutLog = []obj{{
	"name":         "envoy.access_loggers.stdout",
	"typed_config": typed("envoy.extensions.access_loggers.stream.v3.StdoutAccessLog", nil),
}}

type cidr struct {
	prefix netip.Prefix
	from   string
}

// Translate returns the Envoy bootstrap (JSON) for the intent.
func Translate(in *v1.EgressIntent) ([]byte, error) {
	if in.APIVersion != v1.APIVersion || in.Kind != v1.Kind {
		return nil, fmt.Errorf("not an %s %s: apiVersion %q kind %q", v1.APIVersion, v1.Kind, in.APIVersion, in.Kind)
	}
	l := in.Listeners
	switch {
	case l.Transparent < 1 || l.Transparent > 65535:
		return nil, fmt.Errorf("listeners.transparent %d is not a port", l.Transparent)
	case l.DNS != 0:
		return nil, fmt.Errorf("listeners.dns is set: this translator does not serve DNS (leave it unset and KubeSwift resolves only allowed names)")
	case l.HTTP != 0:
		return nil, fmt.Errorf("listeners.http is set: this translator has no explicit HTTP proxy listener")
	case len(in.Credentials) > 0:
		return nil, fmt.Errorf("credentials are not supported by this translator yet")
	}

	tlsHosts := map[int][]string{}
	httpHosts := map[int][]string{}
	cidrByPort := map[int][]cidr{} // port 0: every port
	ports := map[int]bool{}
	for i, r := range in.Allow {
		if r.TLS != nil {
			return nil, fmt.Errorf("allow[%d] (%s): TLS origination is not supported by this translator yet", i, r.From)
		}
		rulePorts := []int{}
		for _, p := range r.Ports {
			if p.Port < 1 || p.Port > 65535 || (p.Protocol != "" && p.Protocol != "TCP") {
				return nil, fmt.Errorf("allow[%d] (%s): port %d/%s", i, r.From, p.Port, p.Protocol)
			}
			rulePorts = append(rulePorts, int(p.Port))
		}
		switch {
		case r.Host != "" && r.CIDR != "":
			return nil, fmt.Errorf("allow[%d] (%s): host and cidr both set", i, r.From)
		case r.Host != "":
			if len(rulePorts) == 0 {
				tlsHosts[defaultTLSPort] = append(tlsHosts[defaultTLSPort], r.Host)
				httpHosts[defaultHTTPPort] = append(httpHosts[defaultHTTPPort], r.Host)
				ports[defaultTLSPort], ports[defaultHTTPPort] = true, true
			}
			for _, p := range rulePorts {
				tlsHosts[p] = append(tlsHosts[p], r.Host)
				httpHosts[p] = append(httpHosts[p], r.Host)
				ports[p] = true
			}
		case r.CIDR != "":
			pfx, err := netip.ParsePrefix(r.CIDR)
			if err != nil || !pfx.Addr().Is4() {
				return nil, fmt.Errorf("allow[%d] (%s): cidr %q is not an IPv4 prefix", i, r.From, r.CIDR)
			}
			c := cidr{prefix: pfx.Masked(), from: r.From}
			if len(rulePorts) == 0 {
				cidrByPort[0] = append(cidrByPort[0], c)
			}
			for _, p := range rulePorts {
				cidrByPort[p] = append(cidrByPort[p], c)
				ports[p] = true
			}
		default:
			return nil, fmt.Errorf("allow[%d] (%s): neither host nor cidr", i, r.From)
		}
	}
	// A cidr rule for every port also holds on each port another chain names.
	for p := range ports {
		cidrByPort[p] = append(cidrByPort[p], cidrByPort[0]...)
	}

	var chains []obj
	for _, p := range sortedKeys(cidrByPort) {
		cs := cidrByPort[p]
		if len(cs) == 0 {
			continue
		}
		match := obj{"prefix_ranges": prefixRanges(cs)}
		if p != 0 {
			match["destination_port"] = p
		}
		chains = append(chains, obj{
			"name":               chainName("cidr", p),
			"filter_chain_match": match,
			"filters": []obj{{
				"name": "envoy.filters.network.tcp_proxy",
				"typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", obj{
					"stat_prefix": "cidr", "cluster": originalDstCluster, "access_log": stdoutLog,
				}),
			}},
		})
	}
	for _, p := range sortedKeys(tlsHosts) {
		chains = append(chains, obj{
			"name": chainName("tls", p),
			"filter_chain_match": obj{
				"destination_port": p, "transport_protocol": "tls", "server_names": dedupe(tlsHosts[p]),
			},
			"filters": []obj{
				{
					"name": "envoy.filters.network.sni_dynamic_forward_proxy",
					"typed_config": typed("envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig", obj{
						"port_value": p, "dns_cache_config": dnsCache,
					}),
				},
				{
					"name": "envoy.filters.network.tcp_proxy",
					"typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", obj{
						"stat_prefix": "tls", "cluster": dfpCluster, "access_log": stdoutLog,
					}),
				},
			},
		})
	}
	for _, p := range sortedKeys(httpHosts) {
		chains = append(chains, httpChain(p, dedupe(httpHosts[p])))
	}

	bootstrap := obj{
		"static_resources": obj{
			"listeners": []obj{{
				"name":    "transparent",
				"address": obj{"socket_address": obj{"address": "0.0.0.0", "port_value": l.Transparent}},
				"listener_filters": []obj{
					{"name": "envoy.filters.listener.original_dst", "typed_config": typed("envoy.extensions.filters.listener.original_dst.v3.OriginalDst", nil)},
					{"name": "envoy.filters.listener.tls_inspector", "typed_config": typed("envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector", nil)},
					{"name": "envoy.filters.listener.http_inspector", "typed_config": typed("envoy.extensions.filters.listener.http_inspector.v3.HttpInspector", nil)},
				},
				"filter_chains": chains,
			}},
			"clusters": []obj{
				{"name": originalDstCluster, "type": "ORIGINAL_DST", "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s"},
				{
					"name": dfpCluster, "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s",
					"cluster_type": obj{
						"name":         "envoy.clusters.dynamic_forward_proxy",
						"typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{"dns_cache_config": dnsCache}),
					},
				},
			},
		},
	}
	return json.MarshalIndent(bootstrap, "", "  ")
}

// httpChain serves plain HTTP on port p: a virtual host per allowed host
// (the Host header, with the port unless it is 80), forwarded to the name's
// address; any other Host gets 403.
func httpChain(p int, hosts []string) obj {
	var vhosts []obj
	for _, h := range hosts {
		domains := []string{h + ":" + strconv.Itoa(p)}
		if p == defaultHTTPPort {
			domains = []string{h, h + ":80"}
		}
		vhosts = append(vhosts, obj{
			"name": "host-" + h, "domains": domains,
			"routes": []obj{{"match": obj{"prefix": "/"}, "route": obj{"cluster": dfpCluster}}},
		})
	}
	vhosts = append(vhosts, obj{
		"name": "deny", "domains": []string{"*"},
		"routes": []obj{{"match": obj{"prefix": "/"}, "direct_response": obj{"status": 403}}},
	})
	return obj{
		"name": chainName("http", p),
		"filter_chain_match": obj{
			"destination_port": p, "transport_protocol": "raw_buffer", "application_protocols": []string{"http/1.0", "http/1.1"},
		},
		"filters": []obj{{
			"name": "envoy.filters.network.http_connection_manager",
			"typed_config": typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
				"stat_prefix":  "http",
				"access_log":   stdoutLog,
				"route_config": obj{"name": "egress", "virtual_hosts": vhosts},
				"http_filters": []obj{
					{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig", obj{"dns_cache_config": dnsCache})},
					{"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router", nil)},
				},
			}),
		}},
	}
}

func prefixRanges(cs []cidr) []obj {
	seen := map[netip.Prefix]bool{}
	var ps []netip.Prefix
	for _, c := range cs {
		if !seen[c.prefix] {
			seen[c.prefix] = true
			ps = append(ps, c.prefix)
		}
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
	out := make([]obj, 0, len(ps))
	for _, p := range ps {
		out = append(out, obj{"address_prefix": p.Addr().String(), "prefix_len": p.Bits()})
	}
	return out
}

func chainName(kind string, port int) string {
	if port == 0 {
		return kind + "-any"
	}
	return kind + "-" + strconv.Itoa(port)
}

func sortedKeys[V any](m map[int]V) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
