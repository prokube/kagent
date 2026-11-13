package egressceiling

import (
	"testing"

	"github.com/stretchr/testify/require"
	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/kagent-dev/kagent/go/core/internal/egress"
	"github.com/kagent-dev/kagent/go/core/internal/substrate"
)

func https(port int32, hostnames ...string) *ateapipb.EgressRule {
	return &ateapipb.EgressRule{Https: &ateapipb.HttpsRule{Hostnames: hostnames, Ports: &ateapipb.Ports{Numbers: []int32{port}}}}
}

func http(port int32, hostnames ...string) *ateapipb.EgressRule {
	return &ateapipb.EgressRule{Http: &ateapipb.HttpRule{Hostnames: hostnames, Ports: &ateapipb.Ports{Numbers: []int32{port}}}}
}

func withCredential(rule *ateapipb.EgressRule) *ateapipb.EgressRule {
	effects := &ateapipb.HttpRuleEffects{ReplaceHeaders: []*ateapipb.CredentialHeader{{Header: "x-api-key", CredentialUri: "secret://team/key"}}}
	if rule.GetHttps() != nil {
		rule.GetHttps().Effects = effects
	} else {
		rule.GetHttp().Effects = effects
	}
	return rule
}

func TestLimit(t *testing.T) {
	tls := func(host string, port int32) Destination { return Destination{Host: host, Port: port, Kind: KindHTTPS} }
	for _, test := range []struct {
		name    string
		rules   []*ateapipb.EgressRule
		profile Profile
		want    []*ateapipb.EgressRule
	}{{
		name:  "no destinations keeps only internal names",
		rules: []*ateapipb.EgressRule{https(443, "example.com"), http(80, "agentgateway-proxy.agentgateway-system.svc.cluster.local"), http(8083, "kagent-controller.kagent.svc"), http(80, "*.team.svc.cluster.local")},
		want:  []*ateapipb.EgressRule{http(80, "agentgateway-proxy.agentgateway-system.svc.cluster.local"), http(8083, "kagent-controller.kagent.svc"), http(80, "*.team.svc.cluster.local")},
	}, {
		name:    "allowed rules stay unchanged with their credentials",
		rules:   []*ateapipb.EgressRule{withCredential(https(443, "api.example.com")), https(443, "example.com")},
		profile: Profile{Destinations: []Destination{tls("api.example.com", 443)}},
		want:    []*ateapipb.EgressRule{withCredential(https(443, "api.example.com"))},
	}, {
		name:    "a profile wildcard covers one label",
		rules:   []*ateapipb.EgressRule{https(443, "a.example.com"), https(443, "a.b.example.com"), https(443, "example.com"), https(443, "*.example.com")},
		profile: Profile{Destinations: []Destination{tls("*.example.com", 443)}},
		want:    []*ateapipb.EgressRule{https(443, "a.example.com"), https(443, "*.example.com")},
	}, {
		name:    "an actor wildcard narrows to the profile's exact hosts",
		rules:   []*ateapipb.EgressRule{https(443, "*.example.com")},
		profile: Profile{Destinations: []Destination{tls("b.example.com", 443), tls("a.example.com", 443), tls("a.b.example.com", 443), tls("*.sub.example.com", 443)}},
		want:    []*ateapipb.EgressRule{https(443, "a.example.com", "b.example.com")},
	}, {
		name:    "narrowing does not repeat a name another rule allows",
		rules:   []*ateapipb.EgressRule{https(443, "*.example.com"), withCredential(https(443, "api.example.com"))},
		profile: Profile{Destinations: []Destination{tls("api.example.com", 443)}},
		want:    []*ateapipb.EgressRule{withCredential(https(443, "api.example.com"))},
	}, {
		name:    "ports and kinds must match",
		rules:   []*ateapipb.EgressRule{https(8443, "api.example.com"), http(80, "api.example.com"), http(80, "plain.example.com")},
		profile: Profile{Destinations: []Destination{tls("api.example.com", 443), {Host: "plain.example.com", Port: 80, Kind: KindHTTP}}},
		want:    []*ateapipb.EgressRule{http(80, "plain.example.com")},
	}, {
		name:    "a rule with several names and ports splits per port",
		rules:   []*ateapipb.EgressRule{{Https: &ateapipb.HttpsRule{Hostnames: []string{"a.example.com", "b.example.com", "api.team.svc"}, Ports: &ateapipb.Ports{Numbers: []int32{443, 8443}}}}},
		profile: Profile{Destinations: []Destination{tls("a.example.com", 443), tls("b.example.com", 8443)}},
		want: []*ateapipb.EgressRule{
			{Https: &ateapipb.HttpsRule{Hostnames: []string{"api.team.svc"}, Ports: &ateapipb.Ports{Numbers: []int32{443, 8443}}}},
			https(443, "a.example.com"), https(8443, "b.example.com"),
		},
	}, {
		name:    "a rule for every port is limited to the profile's ports",
		rules:   []*ateapipb.EgressRule{{Https: &ateapipb.HttpsRule{Hostnames: []string{"api.example.com"}, Ports: &ateapipb.Ports{All: &ateapipb.AllPorts{}}}}},
		profile: Profile{Destinations: []Destination{tls("api.example.com", 443), tls("api.example.com", 8443), tls("other.example.com", 9443)}},
		want:    []*ateapipb.EgressRule{https(443, "api.example.com"), https(8443, "api.example.com")},
	}, {
		name:    "omitted ports use the rule's default",
		rules:   []*ateapipb.EgressRule{{Https: &ateapipb.HttpsRule{Hostnames: []string{"api.example.com"}}}, {Http: &ateapipb.HttpRule{Hostnames: []string{"api.example.com"}}}},
		profile: Profile{Destinations: []Destination{tls("api.example.com", 443)}},
		want:    []*ateapipb.EgressRule{{Https: &ateapipb.HttpsRule{Hostnames: []string{"api.example.com"}}}},
	}, {
		name:    "TLS passthrough needs a TLS destination",
		rules:   []*ateapipb.EgressRule{{TlsPassthrough: &ateapipb.TlsPassthroughRule{Hostnames: []string{"db.example.com", "other.example.com"}, Ports: &ateapipb.Ports{Numbers: []int32{5432}}}}},
		profile: Profile{Destinations: []Destination{tls("db.example.com", 5432)}},
		want:    []*ateapipb.EgressRule{{TlsPassthrough: &ateapipb.TlsPassthroughRule{Hostnames: []string{"db.example.com"}, Ports: &ateapipb.Ports{Numbers: []int32{5432}}}}},
	}, {
		name:  "unknown rule kinds are dropped",
		rules: []*ateapipb.EgressRule{{}},
	}} {
		t.Run(test.name, func(t *testing.T) {
			policy := &ateapipb.EgressPolicy{Rules: test.rules}
			Limit(policy, test.profile, DefaultInternalSuffixes)
			require.Len(t, policy.GetRules(), len(test.want))
			for i := range test.want {
				require.Truef(t, proto.Equal(test.want[i], policy.GetRules()[i]), "rule %d: want %v, got %v", i, test.want[i], policy.GetRules()[i])
			}
		})
	}
}

// The control-plane origin keeps its Actor JWT under an offline profile.
func TestLimitKeepsBuiltInControlPlaneAccess(t *testing.T) {
	controlPlane := "http://kagent-controller.kagent.svc.cluster.local:8083"
	policy, err := substrate.ActorEgressPolicy("team", []string{controlPlane, "https://example.com"}, []egress.Credential{}, controlPlane)
	require.NoError(t, err)
	require.Len(t, policy.GetRules(), 2)
	var want *ateapipb.EgressRule
	for _, rule := range policy.GetRules() {
		if rule.GetHttp() != nil {
			want = proto.CloneOf(rule)
		}
	}
	require.NotEmpty(t, want.GetHttp().GetEffects().GetReplaceHeaders())
	Limit(policy, Profile{}, DefaultInternalSuffixes)
	require.Len(t, policy.GetRules(), 1)
	require.True(t, proto.Equal(want, policy.GetRules()[0]))
}

func TestCoversAndInternal(t *testing.T) {
	require.True(t, Covers("*.example.com", "a.example.com"))
	require.True(t, Covers("*.example.com", "*.example.com"))
	require.False(t, Covers("*.example.com", "*.a.example.com"))
	require.False(t, Covers("a.example.com", "*.example.com"))
	require.False(t, Covers("*.example.com", ".example.com"))
	require.True(t, Internal("x.ns.svc.cluster.local", DefaultInternalSuffixes))
	require.True(t, Internal("*.ns.svc", DefaultInternalSuffixes))
	require.False(t, Internal("svc.cluster.local", DefaultInternalSuffixes))
	require.False(t, Internal("svc.example.com", DefaultInternalSuffixes))
	require.False(t, Internal("x.svc.cluster.local", []string{""}))
}
