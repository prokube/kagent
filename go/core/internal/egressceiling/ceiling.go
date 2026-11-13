// Package egressceiling limits actor egress to a workspace egress profile.
//
// A profile is the ceiling of a namespace: an actor in that namespace's
// Atespace keeps a rule only as far as the profile also allows it. Internal
// destinations (Kubernetes Service names) are exempt, so the runtime control
// plane, models and MCP servers behind in-cluster gateways keep working.
package egressceiling

import (
	"maps"
	"slices"
	"strings"

	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
	"google.golang.org/protobuf/proto"
)

// Rule kinds as a profile destination grants them.
const (
	KindHTTP  = "http"
	KindHTTPS = "https" // also covers TLS passthrough to the same name and port
)

// Destination is one host and port a profile allows.
type Destination struct {
	// Host is an exact DNS name or a single leading wildcard label ("*.example.com").
	Host string
	Port int32
	Kind string
}

// Profile is the ceiling of one namespace. No destinations means no external access.
type Profile struct {
	Destinations []Destination
}

// DefaultInternalSuffixes name Kubernetes Services.
var DefaultInternalSuffixes = []string{"svc.cluster.local", "svc"}

// Limit restricts policy to profile. Hostnames under internalSuffixes are kept.
// A rule the profile fully allows is kept unchanged, including its credential
// effects. A wildcard narrows to the profile's exact hosts it matches, and a
// rule for every port to the profile's ports. Anything else, including rule
// kinds this package does not know, is dropped.
func Limit(policy *ateapipb.EgressPolicy, profile Profile, internalSuffixes []string) {
	kept := map[key]bool{}
	var rules, narrowed []*ateapipb.EgressRule
	for _, rule := range policy.GetRules() {
		view, ok := viewOf(rule)
		if !ok {
			continue
		}
		var internal, external []string
		for _, hostname := range view.hostnames {
			if Internal(hostname, internalSuffixes) {
				internal = append(internal, hostname)
			} else {
				external = append(external, hostname)
			}
		}
		ports := view.numbers
		if view.allPorts {
			ports = profile.ports(view.kind)
		}
		allowed := map[int32][]string{}
		full := !view.allPorts
		for _, hostname := range external {
			for _, port := range ports {
				hosts := allowedHosts(hostname, port, view.kind, profile)
				full = full && slices.Equal(hosts, []string{hostname})
				allowed[port] = appendNew(allowed[port], hosts...)
			}
		}
		if len(external) == 0 || full {
			rules = append(rules, rule)
			for _, hostname := range external {
				for _, port := range ports {
					kept[key{view.kind, hostname, port}] = true
				}
			}
			continue
		}
		if len(internal) != 0 {
			copied := proto.CloneOf(rule)
			setHostnames(copied, internal)
			rules = append(rules, copied)
		}
		for _, port := range slices.Sorted(maps.Keys(allowed)) {
			copied := proto.CloneOf(rule)
			setHostnames(copied, allowed[port])
			setPorts(copied, &ateapipb.Ports{Numbers: []int32{port}})
			narrowed = append(narrowed, copied)
		}
	}
	// A narrowed wildcard must not repeat a name and port another rule already
	// allows, which may carry credentials for it.
	for _, rule := range narrowed {
		view, _ := viewOf(rule)
		port := view.numbers[0]
		hostnames := slices.DeleteFunc(slices.Clone(view.hostnames), func(hostname string) bool { return kept[key{view.kind, hostname, port}] })
		if len(hostnames) != 0 {
			setHostnames(rule, hostnames)
			rules = append(rules, rule)
		}
	}
	policy.Rules = rules
}

type key struct {
	kind, host string
	port       int32
}

// allowedHosts returns the part of hostname:port the profile allows.
func allowedHosts(hostname string, port int32, kind string, profile Profile) []string {
	var hosts []string
	for _, destination := range profile.Destinations {
		if destination.Port != port || destination.Kind != kind {
			continue
		}
		switch {
		case Covers(destination.Host, hostname):
			return []string{hostname}
		case Covers(hostname, destination.Host):
			hosts = appendNew(hosts, destination.Host)
		}
	}
	slices.Sort(hosts)
	return hosts
}

// Covers reports whether pattern matches every name host matches. A wildcard
// replaces exactly one leftmost label.
func Covers(pattern, host string) bool {
	if pattern == host {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok || strings.HasPrefix(host, "*.") {
		return false
	}
	label, rest, ok := strings.Cut(host, ".")
	return ok && label != "" && rest == suffix
}

// Internal reports whether hostname is under one of suffixes.
func Internal(hostname string, suffixes []string) bool {
	hostname = strings.TrimPrefix(hostname, "*.")
	for _, suffix := range suffixes {
		if suffix != "" && strings.HasSuffix(hostname, "."+suffix) {
			return true
		}
	}
	return false
}

func appendNew(list []string, values ...string) []string {
	for _, value := range values {
		if !slices.Contains(list, value) {
			list = append(list, value)
		}
	}
	return list
}

// ruleView is the part of an HTTP, HTTPS or TLS passthrough rule the ceiling reads.
type ruleView struct {
	kind      string
	hostnames []string
	numbers   []int32
	allPorts  bool
}

func viewOf(rule *ateapipb.EgressRule) (ruleView, bool) {
	var hostnames []string
	var ports *ateapipb.Ports
	var kind string
	var defaultPort int32
	switch {
	case rule.GetHttp() != nil:
		kind, hostnames, ports, defaultPort = KindHTTP, rule.GetHttp().GetHostnames(), rule.GetHttp().GetPorts(), 80
	case rule.GetHttps() != nil:
		kind, hostnames, ports, defaultPort = KindHTTPS, rule.GetHttps().GetHostnames(), rule.GetHttps().GetPorts(), 443
	case rule.GetTlsPassthrough() != nil:
		kind, hostnames, ports, defaultPort = KindHTTPS, rule.GetTlsPassthrough().GetHostnames(), rule.GetTlsPassthrough().GetPorts(), 443
	default:
		return ruleView{}, false
	}
	view := ruleView{kind: kind, hostnames: hostnames, numbers: ports.GetNumbers(), allPorts: ports.GetAll() != nil}
	if ports == nil || (!view.allPorts && len(view.numbers) == 0) {
		view.numbers = []int32{defaultPort}
	}
	return view, true
}

// ports lists the profile's ports of kind.
func (p Profile) ports(kind string) []int32 {
	var ports []int32
	for _, destination := range p.Destinations {
		if destination.Kind == kind && !slices.Contains(ports, destination.Port) {
			ports = append(ports, destination.Port)
		}
	}
	slices.Sort(ports)
	return ports
}

func setHostnames(rule *ateapipb.EgressRule, hostnames []string) {
	switch {
	case rule.GetHttp() != nil:
		rule.GetHttp().Hostnames = hostnames
	case rule.GetHttps() != nil:
		rule.GetHttps().Hostnames = hostnames
	case rule.GetTlsPassthrough() != nil:
		rule.GetTlsPassthrough().Hostnames = hostnames
	}
}

func setPorts(rule *ateapipb.EgressRule, ports *ateapipb.Ports) {
	switch {
	case rule.GetHttp() != nil:
		rule.GetHttp().Ports = ports
	case rule.GetHttps() != nil:
		rule.GetHttps().Ports = ports
	case rule.GetTlsPassthrough() != nil:
		rule.GetTlsPassthrough().Ports = ports
	}
}
