// SPDX-License-Identifier: Apache-2.0

package envoy

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// httpProxyListener is the explicit HTTP proxy on port: CONNECT tunnels and
// absolute-URI requests, matched by the authority the guest asked for.
//
// A host rule is a virtual host per host and port ("host:port", and the bare
// name for port 80, which is how an http:// URL without a port arrives); its
// CONNECT route tunnels and its other route forwards, both to the name's own
// address through the dynamic forward proxy. Every other authority lands in
// the catch-all virtual host, where a cidr rule matches an IPv4 literal in
// its prefix on an allowed port, and the rest is answered 403. A name never
// reaches the catch-all routes: their expressions match dotted IPv4 literals
// only.
func httpProxyListener(port int, ownerNS string, tlsHosts, httpHosts map[int][]string, cidrByPort map[int][]cidr, services []serviceRule) (obj, []obj) {
	hostPorts := map[string]map[int]bool{}
	for _, m := range []map[int][]string{tlsHosts, httpHosts} {
		for p, hs := range m {
			for _, h := range hs {
				if hostPorts[h] == nil {
					hostPorts[h] = map[int]bool{}
				}
				hostPorts[h][p] = true
			}
		}
	}
	hosts := make([]string, 0, len(hostPorts))
	for h := range hostPorts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var vhosts []obj
	for _, h := range hosts {
		for _, p := range sortedKeys(hostPorts[h]) {
			domains := []string{h + ":" + strconv.Itoa(p)}
			if p == defaultHTTPPort {
				domains = append(domains, h)
			}
			vhosts = append(vhosts, obj{
				"name": "host-" + h + "-" + strconv.Itoa(p), "domains": domains,
				"routes": []obj{connectRoute(nil), forwardRoute(nil)},
			})
		}
	}

	var routes, clusters []obj
	seen := map[string]bool{}
	for _, sv := range services {
		for _, p := range sv.ports {
			cl := "service_" + sv.addr + "_" + strconv.Itoa(p)
			if !seen[cl] {
				seen[cl] = true
				clusters = append(clusters, obj{
					"name": cl, "type": "STATIC", "connect_timeout": "5s",
					"load_assignment": obj{"cluster_name": cl, "endpoints": []obj{{"lb_endpoints": []obj{{
						"endpoint": obj{"address": obj{"socket_address": obj{"address": sv.addr, "port_value": p}}},
					}}}}},
				})
			}
			re := sv.authorityRegex(ownerNS, p)
			routes = append(routes, connectRouteTo(cl, &re), forwardRouteTo(cl, &re))
		}
	}
	for _, p := range sortedKeys(cidrByPort) {
		cs := cidrByPort[p]
		if len(cs) == 0 {
			continue
		}
		re := authorityRegex(cs, p)
		routes = append(routes, connectRoute(re), forwardRoute(re))
	}
	deny := obj{"direct_response": obj{"status": 403}}
	routes = append(routes,
		merge(obj{"match": obj{"connect_matcher": obj{}}}, deny),
		merge(obj{"match": obj{"prefix": "/"}}, deny),
	)
	vhosts = append(vhosts, obj{"name": "address", "domains": []string{"*"}, "routes": routes})

	return obj{
		"name":    "http",
		"address": obj{"socket_address": obj{"address": "0.0.0.0", "port_value": port}},
		"filter_chains": []obj{{
			"name": "http-proxy",
			"filters": []obj{{
				"name": "envoy.filters.network.http_connection_manager",
				"typed_config": typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
					"stat_prefix":           "http_proxy",
					"access_log":            stdoutLog,
					"http_protocol_options": obj{"allow_absolute_url": true},
					"upgrade_configs":       []obj{{"upgrade_type": "CONNECT"}},
					"route_config":          obj{"name": "http_proxy", "virtual_hosts": vhosts},
					"http_filters": []obj{
						{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig", obj{"dns_cache_config": dnsCache})},
						{"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router", nil)},
					},
				}),
			}},
		}},
	}, clusters
}

// serviceRule is a cidr rule resolved from a Service, with its ports.
type serviceRule struct {
	namespace, name, addr string
	ports                 []int
}

// authorityRegex matches the Service's names on port: "name" when it is in
// the owner's namespace, "name.ns", "name.ns.svc" and "name.ns.svc.<domain>"
// (as KubeSwift's built-in broker accepts them).
func (s serviceRule) authorityRegex(ownerNS string, port int) string {
	n, ns := regexp.QuoteMeta(s.name), regexp.QuoteMeta(s.namespace)
	names := []string{n + `\.` + ns, n + `\.` + ns + `\.svc`, n + `\.` + ns + `\.svc\.[a-z0-9]([-a-z0-9.]*[a-z0-9])?`}
	if s.namespace == ownerNS {
		names = append([]string{n}, names...)
	}
	portRE := ":" + strconv.Itoa(port)
	if port == defaultHTTPPort {
		portRE = "(:80)?"
	}
	return "(" + strings.Join(names, "|") + ")" + portRE
}

// connectRoute terminates a CONNECT request (optionally only for an
// :authority matching re) and tunnels its bytes to the authority.
func connectRoute(re *string) obj { return connectRouteTo(dfpCluster, re) }

func connectRouteTo(cluster string, re *string) obj {
	m := obj{"connect_matcher": obj{}}
	authorityMatch(m, re)
	return obj{"match": m, "route": obj{
		"cluster":         cluster,
		"upgrade_configs": []obj{{"upgrade_type": "CONNECT", "connect_config": obj{}}},
	}}
}

// forwardRoute forwards any other request (optionally only for an
// :authority matching re) to the authority.
func forwardRoute(re *string) obj { return forwardRouteTo(dfpCluster, re) }

func forwardRouteTo(cluster string, re *string) obj {
	m := obj{"prefix": "/"}
	authorityMatch(m, re)
	return obj{"match": m, "route": obj{"cluster": cluster}}
}

func authorityMatch(m obj, re *string) {
	if re != nil {
		m["headers"] = []obj{{"name": ":authority", "string_match": obj{"safe_regex": obj{"regex": *re}}}}
	}
}

func merge(a, b obj) obj {
	for k, v := range b {
		a[k] = v
	}
	return a
}

// octetRE matches a decimal octet without leading zeros.
const octetRE = `(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`

// authorityRegex matches "a.b.c.d:port" (and, for port 80, "a.b.c.d") for
// an address inside one of cs. Port 0 is any port. Envoy matches the whole
// value.
func authorityRegex(cs []cidr, port int) *string {
	seen := map[netip.Prefix]bool{}
	var alts []string
	for _, c := range cs {
		if seen[c.prefix] {
			continue
		}
		seen[c.prefix] = true
		alts = append(alts, prefixRegex(c.prefix))
	}
	sort.Strings(alts)
	var portRE string
	switch port {
	case 0:
		portRE = `(:[0-9]{1,5})?`
	case defaultHTTPPort:
		portRE = `(:80)?`
	default:
		portRE = ":" + strconv.Itoa(port)
	}
	re := "(" + strings.Join(alts, "|") + ")" + portRE
	return &re
}

// prefixRegex matches the dotted IPv4 addresses inside p.
func prefixRegex(p netip.Prefix) string {
	a := p.Addr().As4()
	bits := p.Bits()
	parts := make([]string, 4)
	for i := 0; i < 4; i++ {
		fixed := bits - 8*i // bits of this octet the prefix fixes
		switch {
		case fixed >= 8:
			parts[i] = strconv.Itoa(int(a[i]))
		case fixed <= 0:
			parts[i] = octetRE
		default:
			lo := int(a[i])
			n := 1 << (8 - fixed)
			vals := make([]string, 0, n)
			for v := lo; v < lo+n; v++ {
				vals = append(vals, strconv.Itoa(v))
			}
			parts[i] = "(" + strings.Join(vals, "|") + ")"
		}
	}
	return strings.Join(parts, `\.`)
}
