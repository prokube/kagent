package egressceiling

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kagent-dev/kagent/go/core/pkg/egresspolicy"
)

func namespace(name string, controlled bool) *corev1.Namespace {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if controlled {
		ns.Labels = map[string]string{NamespaceLabel: NamespaceLabelValue}
	}
	return ns
}

// serviceEntry renders a ServiceEntry the way the profile writer does.
func serviceEntry(namespace, name string, labels map[string]string, hosts []string, ports ...map[string]any) *unstructured.Unstructured {
	entry := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"hosts": toAny(hosts), "location": "MESH_EXTERNAL", "resolution": "DNS", "ports": toAny(ports),
	}}}
	entry.SetGroupVersionKind(ServiceEntryGVK)
	entry.SetNamespace(namespace)
	entry.SetName(name)
	entry.SetLabels(labels)
	return entry
}

func toAny[T any](values []T) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func port(number int64, protocol string) map[string]any {
	return map[string]any{"number": number, "protocol": protocol, "name": protocol + "-port"}
}

func testCompiler(t *testing.T, objects ...client.Object) *Compiler {
	t.Helper()
	scheme := k8sruntime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	scheme.AddKnownTypeWithName(ServiceEntryGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(ServiceEntryGVK.GroupVersion().WithKind("ServiceEntryList"), &unstructured.UnstructuredList{})
	compiler := New(DefaultInternalSuffixes)
	compiler.reader = fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	return compiler
}

func TestProfileReadsTheWorkspaceProfile(t *testing.T) {
	profileLabels := map[string]string{ManagedByLabel: ManagedByValue, ProfileLabel: "packages"}
	compiler := testCompiler(t,
		namespace("plain", false), namespace("offline", true), namespace("team", true),
		serviceEntry("team", "pkui-egress-team", profileLabels, []string{"pypi.org", "*.example.com"}, port(443, "TLS"), port(80, "HTTP"), port(5432, "TCP")),
		// Not rendered from a profile: users and other tools cannot widen the ceiling.
		serviceEntry("team", "unlabelled", nil, []string{"evil.example.org"}, port(443, "TLS")),
		serviceEntry("team", "other-writer", map[string]string{ManagedByLabel: "someone", ProfileLabel: "x"}, []string{"evil.example.org"}, port(443, "TLS")),
		serviceEntry("offline", "unlabelled", nil, []string{"evil.example.org"}, port(443, "TLS")),
	)
	ctx := t.Context()

	_, ok, err := compiler.Profile(ctx, "plain")
	require.NoError(t, err)
	require.False(t, ok)

	profile, ok, err := compiler.Profile(ctx, "offline")
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, profile.Destinations)

	profile, ok, err = compiler.Profile(ctx, "team")
	require.NoError(t, err)
	require.True(t, ok)
	require.ElementsMatch(t, []Destination{
		{Host: "pypi.org", Port: 443, Kind: KindHTTPS}, {Host: "*.example.com", Port: 443, Kind: KindHTTPS},
		{Host: "pypi.org", Port: 80, Kind: KindHTTP}, {Host: "*.example.com", Port: 80, Kind: KindHTTP},
	}, profile.Destinations)

	_, _, err = compiler.Profile(ctx, "missing")
	require.Error(t, err, "an Atespace without its namespace fails closed")
}

func TestCompileAppliesTheCeilingOnlyToControlledAtespaces(t *testing.T) {
	compiler := testCompiler(t, namespace("plain", false), namespace("offline", true))
	rules := func() *ateapipb.EgressPolicy {
		return &ateapipb.EgressPolicy{Rules: []*ateapipb.EgressRule{https(443, "example.com"), http(8083, "kagent-controller.kagent.svc.cluster.local")}}
	}
	policy := rules()
	require.NoError(t, compiler.Compile(t.Context(), egresspolicy.Input{Atespace: "plain"}, policy))
	require.Len(t, policy.GetRules(), 2)
	policy = rules()
	require.NoError(t, compiler.Compile(t.Context(), egresspolicy.Input{Atespace: "offline"}, policy))
	require.Len(t, policy.GetRules(), 1)
	require.Equal(t, []string{"kagent-controller.kagent.svc.cluster.local"}, policy.GetRules()[0].GetHttp().GetHostnames())
}

func TestCompileFailsBeforeProfilesAreLoaded(t *testing.T) {
	require.Error(t, New(nil).Compile(t.Context(), egresspolicy.Input{Atespace: "team"}, &ateapipb.EgressPolicy{}))
}

func TestChangedCoalescesNotifications(t *testing.T) {
	compiler := New(nil)
	compiler.notify("b")
	compiler.notify("a")
	compiler.notify("b")
	changed, err := compiler.Changed(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, changed)

	done := make(chan []string)
	go func() {
		changed, _ := compiler.Changed(t.Context())
		done <- changed
	}()
	time.Sleep(10 * time.Millisecond)
	compiler.notify("c")
	require.Equal(t, []string{"c"}, <-done)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = compiler.Changed(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestEventFilters(t *testing.T) {
	require.True(t, controlled(namespace("team", true)))
	require.False(t, controlled(namespace("team", false)))
	require.True(t, profileEntry(serviceEntry("team", "x", map[string]string{ManagedByLabel: ManagedByValue, ProfileLabel: "p"}, nil)))
	require.False(t, profileEntry(serviceEntry("team", "x", map[string]string{ManagedByLabel: ManagedByValue}, nil)))
}
