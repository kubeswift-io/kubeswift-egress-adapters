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
//
//   - host rules match the TLS server name (tls_inspector) or, for plain
//     HTTP, the Host header (http_inspector + a route per host), and forward
//     to the address the NAME resolves to (dynamic forward proxy), never to
//     the original destination. A spoofed server name therefore cannot reach
//     another address.
//
//   - a credential destination (host:port) gets its own chain: Envoy
//     terminates the guest's TLS with the leaf certificate KubeSwift issued
//     for the host, sets the credential's header from its file
//     (credential_injector), refuses any other Host with 403 and forwards
//     over TLS, verified against the image's CA bundle, to the address the
//     name resolves to. The certificates and values are read through SDS
//     files that watch the intent's secretsDir, so a warm slot's claim
//     reloads them without a restart. An empty value answers 401.
//
//   - a rule with tls (originate SPIFFE) gets the same match, but the guest
//     speaks plaintext and Envoy connects over TLS presenting the sandbox's
//     X.509-SVID, read over SDS from the SPIFFE agent at
//     identity.spiffe.workloadAPISocket (SPIRE's SDS: the "default" SVID and
//     the "ROOTCA" bundle), and accepts only an upstream SVID of the
//     sandbox's trust domain (a URI SAN under spiffe://<trust domain>/). A
//     host rule with tls is served on its ports as plain HTTP (the Host
//     header picks the rule) and forwarded with SNI; it needs ports.
//
// A connection that matches no chain is closed.
//
// Envoy matches the destination port before anything else, and a chain that
// names no port is used for a port only when no chain names it. So a cidr
// rule for every port is repeated for each port another rule names, or a
// host rule on 443 would hide it.
//
// Not supported, refused with an error: a DNS or HTTP listener, wildcard
// credential destinations and an intercept CA key without issued
// certificates (this translator cannot mint).
package envoy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/kubeswift-io/kubeswift-egress-adapters/intent/v1"
)

const (
	originalDstCluster = "original_dst"
	dfpCluster         = "dynamic_forward_proxy"
	dfpTLSCluster      = "dynamic_forward_proxy_tls"
	// TLS origination with the sandbox's SVID.
	originalDstSPIFFECluster = "original_dst_spiffe"
	dfpSPIFFECluster         = "dynamic_forward_proxy_spiffe"
	spiffeAgentCluster       = "spiffe_workload_api"
	secretType               = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"
	dnsCacheName             = "egress_dns_cache"
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

// Options are what the intent does not say.
type Options struct {
	// Dir is the absolute directory the output files are written to; the
	// bootstrap names the SDS files in it.
	Dir string
	// AdminPort, when set, opens Envoy's admin endpoint on 127.0.0.1 (for a
	// readiness probe; its /certs page lists the serving certificates).
	AdminPort int
	// UpstreamCA is the CA bundle intercepted connections verify upstream
	// servers against. Default /etc/ssl/certs/ca-certificates.crt (the
	// Envoy image's).
	UpstreamCA string
	// SVIDName and BundleName are the SDS resource names of the SVID and of
	// the trust domain's bundle at the SPIFFE agent. Default "default" and
	// "ROOTCA" (SPIRE's).
	SVIDName, BundleName string
}

// BootstrapFile is the name of the bootstrap in the output.
const BootstrapFile = "envoy.json"

// Translate returns the files to write into opt.Dir: BootstrapFile and, with
// credentials, one SDS file per certificate and credential.
func Translate(in *v1.EgressIntent, opt Options) (map[string][]byte, error) {
	if !filepath.IsAbs(opt.Dir) {
		return nil, fmt.Errorf("output directory %q is not absolute", opt.Dir)
	}
	if opt.UpstreamCA == "" {
		opt.UpstreamCA = "/etc/ssl/certs/ca-certificates.crt"
	}
	if opt.SVIDName == "" {
		opt.SVIDName = "default"
	}
	if opt.BundleName == "" {
		opt.BundleName = "ROOTCA"
	}
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
	}

	tlsHosts := map[int][]string{}
	httpHosts := map[int][]string{}
	spiffeHosts := map[int]map[string]bool{} // host rules with tls, per port
	cidrByPort := map[int][]cidr{}           // port 0: every port
	spiffeCIDRByPort := map[int][]cidr{}
	ports := map[int]bool{}
	anyOriginate := false
	for i, r := range in.Allow {
		originate := false
		if r.TLS != nil {
			if r.TLS.Originate != "SPIFFE" {
				return nil, fmt.Errorf("allow[%d] (%s): tls.originate %q is not SPIFFE", i, r.From, r.TLS.Originate)
			}
			originate = true
			anyOriginate = true
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
		case r.Host != "" && originate:
			if len(rulePorts) == 0 {
				return nil, fmt.Errorf("allow[%d] (%s): a host rule with tls needs ports (the guest speaks HTTP on them)", i, r.From)
			}
			for _, p := range rulePorts {
				httpHosts[p] = append(httpHosts[p], r.Host)
				if spiffeHosts[p] == nil {
					spiffeHosts[p] = map[string]bool{}
				}
				spiffeHosts[p][r.Host] = true
				ports[p] = true
			}
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
			byPort := cidrByPort
			if originate {
				byPort = spiffeCIDRByPort
			}
			if len(rulePorts) == 0 {
				byPort[0] = append(byPort[0], c)
			}
			for _, p := range rulePorts {
				byPort[p] = append(byPort[p], c)
				ports[p] = true
			}
		default:
			return nil, fmt.Errorf("allow[%d] (%s): neither host nor cidr", i, r.From)
		}
	}
	files := map[string][]byte{}
	icepts, err := intercepts(in, tlsHosts, opt.Dir, files)
	if err != nil {
		return nil, err
	}
	for _, ic := range icepts {
		// The intercept chain names the host exactly; the passthrough chain
		// must not name it too (Envoy refuses two equal matches).
		tlsHosts[ic.port] = remove(tlsHosts[ic.port], ic.host)
		if len(tlsHosts[ic.port]) == 0 {
			delete(tlsHosts, ic.port)
		}
	}

	// A cidr rule for every port also holds on each port another chain names.
	for p := range ports {
		cidrByPort[p] = append(cidrByPort[p], cidrByPort[0]...)
		spiffeCIDRByPort[p] = append(spiffeCIDRByPort[p], spiffeCIDRByPort[0]...)
	}
	// The same address and port cannot be both spliced and originated.
	for p, cs := range spiffeCIDRByPort {
		for _, c := range cs {
			for _, o := range cidrByPort[p] {
				if o.prefix == c.prefix {
					return nil, fmt.Errorf("%s and %s: the same destination with and without tls", c.from, o.from)
				}
			}
		}
	}
	spiffe, err := spiffeTLS(in, anyOriginate, opt)
	if err != nil {
		return nil, err
	}

	var chains []obj
	for _, kind := range []struct {
		name, cluster string
		byPort        map[int][]cidr
	}{{"cidr", originalDstCluster, cidrByPort}, {"cidr-spiffe", originalDstSPIFFECluster, spiffeCIDRByPort}} {
		for _, p := range sortedKeys(kind.byPort) {
			cs := kind.byPort[p]
			if len(cs) == 0 {
				continue
			}
			match := obj{"prefix_ranges": prefixRanges(cs)}
			if p != 0 {
				match["destination_port"] = p
			}
			chains = append(chains, obj{
				"name":               chainName(kind.name, p),
				"filter_chain_match": match,
				"filters": []obj{{
					"name": "envoy.filters.network.tcp_proxy",
					"typed_config": typed("envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy", obj{
						"stat_prefix": kind.name, "cluster": kind.cluster, "access_log": stdoutLog,
					}),
				}},
			})
		}
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
		chains = append(chains, httpChain(p, dedupe(httpHosts[p]), spiffeHosts[p]))
	}
	for _, ic := range icepts {
		chains = append(chains, ic.chain())
	}
	clusters := []obj{
		{"name": originalDstCluster, "type": "ORIGINAL_DST", "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s"},
		dfpClusterDef(dfpCluster, nil),
	}
	if len(icepts) > 0 {
		clusters = append(clusters, dfpClusterDef(dfpTLSCluster, &opt))
	}
	if spiffe != nil {
		clusters = append(clusters, spiffe.clusters()...)
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
			"clusters": clusters,
		},
	}
	if len(icepts) > 0 || spiffe != nil {
		// SDS needs a node identity.
		bootstrap["node"] = obj{"id": "kubeswift-sandbox", "cluster": "kubeswift-egress"}
	}
	if opt.AdminPort > 0 {
		if opt.AdminPort > 65535 || int32(opt.AdminPort) == l.Transparent {
			return nil, fmt.Errorf("admin port %d is not a free port", opt.AdminPort)
		}
		bootstrap["admin"] = obj{"address": obj{"socket_address": obj{"address": "127.0.0.1", "port_value": opt.AdminPort}}}
	}
	b, err := json.MarshalIndent(bootstrap, "", "  ")
	if err != nil {
		return nil, err
	}
	files[BootstrapFile] = b
	return files, nil
}

func dfpClusterDef(name string, tls *Options) obj {
	c := obj{
		"name": name, "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s",
		"cluster_type": obj{
			"name":         "envoy.clusters.dynamic_forward_proxy",
			"typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{"dns_cache_config": dnsCache}),
		},
	}
	if tls != nil {
		// The upstream server is verified against the name the guest asked
		// for (auto_sni + auto_san_validation take it from the Host).
		c["transport_socket"] = obj{
			"name": "envoy.transport_sockets.tls",
			"typed_config": typed("envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", obj{
				"common_tls_context": obj{"validation_context": obj{"trusted_ca": obj{"filename": tls.UpstreamCA}}},
			}),
		}
		c["typed_extension_protocol_options"] = obj{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
				"upstream_http_protocol_options": obj{"auto_sni": true, "auto_san_validation": true},
				"explicit_http_config":           obj{"http_protocol_options": obj{}},
			}),
		}
	}
	return c
}

// spiffeOrigination is the TLS Envoy originates with the sandbox's SVID.
type spiffeOrigination struct {
	socket, trustDomain string
	opt                 Options
}

// spiffeTLS checks the intent's SPIFFE identity when a rule needs it.
func spiffeTLS(in *v1.EgressIntent, needed bool, opt Options) (*spiffeOrigination, error) {
	if !needed {
		return nil, nil
	}
	if in.Identity == nil || in.Identity.SPIFFE == nil {
		return nil, fmt.Errorf("rules with tls need identity.spiffe")
	}
	sp := in.Identity.SPIFFE
	socket, ok := strings.CutPrefix(sp.WorkloadAPISocket, "unix://")
	if !ok || !filepath.IsAbs(socket) {
		return nil, fmt.Errorf("identity.spiffe.workloadAPISocket %q is not unix:///<absolute path>", sp.WorkloadAPISocket)
	}
	rest, ok := strings.CutPrefix(sp.ID, "spiffe://")
	td, _, _ := strings.Cut(rest, "/")
	if !ok || td == "" {
		return nil, fmt.Errorf("identity.spiffe.id %q has no trust domain", sp.ID)
	}
	return &spiffeOrigination{socket: socket, trustDomain: td, opt: opt}, nil
}

func (s *spiffeOrigination) sds(name string) obj {
	return obj{"name": name, "sds_config": obj{
		"resource_api_version": "V3",
		"api_config_source": obj{
			"api_type": "GRPC", "transport_api_version": "V3",
			"grpc_services": []obj{{"envoy_grpc": obj{"cluster_name": spiffeAgentCluster}}},
		},
	}}
}

// transportSocket presents the SVID and accepts an upstream SVID of the
// trust domain only.
func (s *spiffeOrigination) transportSocket() obj {
	return obj{
		"name": "envoy.transport_sockets.tls",
		"typed_config": typed("envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext", obj{
			"common_tls_context": obj{
				"tls_certificate_sds_secret_configs": []obj{s.sds(s.opt.SVIDName)},
				"combined_validation_context": obj{
					"default_validation_context": obj{"match_typed_subject_alt_names": []obj{{
						"san_type": "URI", "matcher": obj{"prefix": "spiffe://" + s.trustDomain + "/"},
					}}},
					"validation_context_sds_secret_config": s.sds(s.opt.BundleName),
				},
			},
		}),
	}
}

func (s *spiffeOrigination) clusters() []obj {
	od := obj{"name": originalDstSPIFFECluster, "type": "ORIGINAL_DST", "lb_policy": "CLUSTER_PROVIDED", "connect_timeout": "5s",
		"transport_socket": s.transportSocket()}
	dfp := dfpClusterDef(dfpSPIFFECluster, nil)
	// An SVID carries a URI SAN, no DNS name, so Envoy's name check
	// (auto_san_validation) cannot pass; the trust-domain URI SAN match in
	// the transport socket is the check, and the option that lets the
	// cluster go without the name check is set for this cluster only.
	dfp["cluster_type"] = obj{
		"name": "envoy.clusters.dynamic_forward_proxy",
		"typed_config": typed("envoy.extensions.clusters.dynamic_forward_proxy.v3.ClusterConfig", obj{
			"dns_cache_config": dnsCache, "allow_insecure_cluster_options": true,
		}),
	}
	dfp["transport_socket"] = s.transportSocket()
	// SNI from the Host; the SAN is checked against the trust domain, not
	// the name.
	dfp["typed_extension_protocol_options"] = obj{
		"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
			"upstream_http_protocol_options": obj{"auto_sni": true},
			"explicit_http_config":           obj{"http_protocol_options": obj{}},
		}),
	}
	agent := obj{
		"name": spiffeAgentCluster, "type": "STATIC", "connect_timeout": "1s",
		"typed_extension_protocol_options": obj{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed("envoy.extensions.upstreams.http.v3.HttpProtocolOptions", obj{
				"explicit_http_config": obj{"http2_protocol_options": obj{}},
			}),
		},
		"load_assignment": obj{"cluster_name": spiffeAgentCluster, "endpoints": []obj{{"lb_endpoints": []obj{{
			"endpoint": obj{"address": obj{"pipe": obj{"path": s.socket}}},
		}}}}},
	}
	return []obj{od, dfp, agent}
}

var credName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// intercept is one credential destination.
type intercept struct {
	host  string
	port  int
	cert  string // SDS secret name of the leaf certificate
	creds []icred
	sdsFn func(name string) obj
}

type icred struct {
	name, header, sds string
}

// intercepts groups the credentials by destination and writes their SDS
// files into files. tlsHosts are the passthrough TLS names per port: every
// destination must be one of them (or match a wildcard there).
func intercepts(in *v1.EgressIntent, tlsHosts map[int][]string, dir string, files map[string][]byte) ([]*intercept, error) {
	if len(in.Credentials) == 0 {
		return nil, nil
	}
	switch {
	case in.TLS == nil || len(in.TLS.Certificates) == 0:
		return nil, fmt.Errorf("credentials need tls.certificates: this translator cannot mint certificates from the intercept CA")
	case in.SecretsDir == "" || !filepath.IsAbs(in.SecretsDir):
		return nil, fmt.Errorf("credentials need an absolute secretsDir, got %q", in.SecretsDir)
	}
	watch := obj{"path": in.SecretsDir}
	inDir := func(f string) error {
		if filepath.Dir(f) != filepath.Clean(in.SecretsDir) {
			return fmt.Errorf("%s is not in secretsDir %s", f, in.SecretsDir)
		}
		return nil
	}
	sds := func(name string) obj {
		return obj{"name": name, "sds_config": obj{"path_config_source": obj{"path": filepath.Join(dir, "sds-"+name+".json")}}}
	}
	put := func(name string, secret obj) error {
		secret["@type"] = secretType
		secret["name"] = name
		b, err := json.MarshalIndent(obj{"resources": []obj{secret}}, "", "  ")
		files["sds-"+name+".json"] = b
		return err
	}
	certFor := map[string]string{}
	for i, c := range in.TLS.Certificates {
		if err := inDir(c.Cert); err != nil {
			return nil, fmt.Errorf("tls.certificates[%d]: %w", i, err)
		}
		if err := inDir(c.Key); err != nil {
			return nil, fmt.Errorf("tls.certificates[%d]: %w", i, err)
		}
		name := "ks-cert-" + strconv.Itoa(i)
		if err := put(name, obj{"tls_certificate": obj{
			"certificate_chain": obj{"filename": c.Cert},
			"private_key":       obj{"filename": c.Key},
			"watched_directory": watch,
		}}); err != nil {
			return nil, err
		}
		for _, h := range c.Hosts {
			if _, dup := certFor[h]; !dup {
				certFor[h] = name
			}
		}
	}
	byDest := map[string]*intercept{}
	for i, c := range in.Credentials {
		at := fmt.Sprintf("credentials[%d] (%s)", i, c.Name)
		if !credName.MatchString(c.Name) || c.Header == "" {
			return nil, fmt.Errorf("%s: needs a name and a header", at)
		}
		value := c.HeaderValueFile
		if value == "" {
			if c.ValueTemplate != "{}" {
				return nil, fmt.Errorf("%s: value template %q needs headerValueFile (this translator cannot apply a template)", at, c.ValueTemplate)
			}
			value = c.File
		}
		if err := inDir(value); err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
		name := "ks-cred-" + c.Name
		if err := put(name, obj{"generic_secret": obj{"secret": obj{"filename": value, "watched_directory": watch}}}); err != nil {
			return nil, err
		}
		for _, d := range c.Destinations {
			host, ps, err := net.SplitHostPort(d)
			port, perr := strconv.Atoi(ps)
			switch {
			case err != nil || perr != nil || port < 1 || port > 65535:
				return nil, fmt.Errorf("%s: destination %q is not host:port", at, d)
			case strings.HasPrefix(host, "*."):
				return nil, fmt.Errorf("%s: destination %q: wildcard credential destinations are not supported", at, d)
			case !covered(host, tlsHosts[port]):
				return nil, fmt.Errorf("%s: destination %q is not allowed by a host rule on port %d", at, d, port)
			case certFor[host] == "":
				return nil, fmt.Errorf("%s: destination %q has no certificate in tls.certificates", at, d)
			}
			key := host + ":" + strconv.Itoa(port)
			ic := byDest[key]
			if ic == nil {
				ic = &intercept{host: host, port: port, cert: certFor[host]}
				byDest[key] = ic
			}
			for _, o := range ic.creds {
				if strings.EqualFold(o.header, c.Header) {
					return nil, fmt.Errorf("%s: destination %q gets header %s from %s too", at, d, c.Header, o.name)
				}
			}
			ic.creds = append(ic.creds, icred{name: c.Name, header: c.Header, sds: name})
		}
	}
	keys := make([]string, 0, len(byDest))
	for k := range byDest {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*intercept, 0, len(keys))
	for _, k := range keys {
		ic := byDest[k]
		ic.sdsFn = sds
		out = append(out, ic)
	}
	return out, nil
}

// covered: host equals one of names or is under a "*." name in it.
func covered(host string, names []string) bool {
	for _, n := range names {
		if n == host || (strings.HasPrefix(n, "*.") && strings.HasSuffix(host, n[1:])) {
			return true
		}
	}
	return false
}

func (ic *intercept) chain() obj {
	filters := []obj{{"name": "envoy.filters.http.dynamic_forward_proxy", "typed_config": typed("envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig", obj{"dns_cache_config": dnsCache})}}
	for _, c := range ic.creds {
		filters = append(filters, obj{
			"name": "envoy.filters.http.credential_injector",
			"typed_config": typed("envoy.extensions.filters.http.credential_injector.v3.CredentialInjector", obj{
				"overwrite": true,
				"credential": obj{
					"name": "envoy.http.injected_credentials.generic",
					"typed_config": typed("envoy.extensions.http.injected_credentials.generic.v3.Generic", obj{
						"header": c.header, "credential": ic.sdsFn(c.sds),
					}),
				},
			}),
		})
	}
	filters = append(filters, obj{"name": "envoy.filters.http.router", "typed_config": typed("envoy.extensions.filters.http.router.v3.Router", nil)})
	domains := []string{ic.host + ":" + strconv.Itoa(ic.port)}
	if ic.port == defaultTLSPort {
		domains = []string{ic.host, ic.host + ":443"}
	}
	vhosts := []obj{
		{"name": "host-" + ic.host, "domains": domains, "routes": []obj{{"match": obj{"prefix": "/"}, "route": obj{"cluster": dfpTLSCluster}}}},
		{"name": "deny", "domains": []string{"*"}, "routes": []obj{{"match": obj{"prefix": "/"}, "direct_response": obj{"status": 403}}}},
	}
	return obj{
		"name":               "intercept-" + ic.host + "-" + strconv.Itoa(ic.port),
		"filter_chain_match": obj{"destination_port": ic.port, "transport_protocol": "tls", "server_names": []string{ic.host}},
		"transport_socket": obj{
			"name": "envoy.transport_sockets.tls",
			"typed_config": typed("envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext", obj{
				"common_tls_context": obj{
					"tls_certificate_sds_secret_configs": []obj{ic.sdsFn(ic.cert)},
					"alpn_protocols":                     []string{"http/1.1"},
				},
			}),
		},
		"filters": []obj{{
			"name": "envoy.filters.network.http_connection_manager",
			"typed_config": typed("envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager", obj{
				"stat_prefix":  "intercept",
				"access_log":   stdoutLog,
				"route_config": obj{"name": "intercept", "virtual_hosts": vhosts},
				"http_filters": filters,
			}),
		}},
	}
}

func remove(s []string, x string) []string {
	var out []string
	for _, v := range s {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

// httpChain serves plain HTTP on port p: a virtual host per allowed host
// (the Host header, with the port unless it is 80), forwarded to the name's
// address; any other Host gets 403.
func httpChain(p int, hosts []string, spiffe map[string]bool) obj {
	var vhosts []obj
	for _, h := range hosts {
		cluster := dfpCluster
		if spiffe[h] {
			cluster = dfpSPIFFECluster
		}
		domains := []string{h + ":" + strconv.Itoa(p)}
		if p == defaultHTTPPort {
			domains = []string{h, h + ":80"}
		}
		vhosts = append(vhosts, obj{
			"name": "host-" + h, "domains": domains,
			"routes": []obj{{"match": obj{"prefix": "/"}, "route": obj{"cluster": cluster}}},
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
