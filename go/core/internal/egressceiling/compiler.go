package egressceiling

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/kagent-dev/kagent/go/core/pkg/egresspolicy"
)

// Labels the workspace egress profile writer sets.
const (
	// NamespaceLabel marks a namespace that has a profile assigned.
	NamespaceLabel      = "prokube.ai/egress-control"
	NamespaceLabelValue = "enabled"
	// ProfileLabel names the profile a ServiceEntry was rendered from.
	ProfileLabel   = "prokube.ai/egress-profile"
	ManagedByLabel = "prokube.ai/managed-by"
	ManagedByValue = "pkui"
)

// ServiceEntryGVK is the version the profile writer uses.
var ServiceEntryGVK = schema.GroupVersionKind{Group: "networking.istio.io", Version: "v1beta1", Kind: "ServiceEntry"}

var serviceEntrySelector = labels.SelectorFromSet(labels.Set{ManagedByLabel: ManagedByValue})

// Compiler limits each actor's policy to its Atespace's workspace profile.
// Atespaces are named after their namespace. A namespace without
// NamespaceLabel has no ceiling.
type Compiler struct {
	internalSuffixes []string

	mu      sync.Mutex
	reader  client.Reader
	changed map[string]bool
	wake    chan struct{}
}

var (
	_ egresspolicy.Compiler = (*Compiler)(nil)
	_ egresspolicy.Watcher  = (*Compiler)(nil)
)

// New returns a Compiler that exempts hostnames under internalSuffixes.
func New(internalSuffixes []string) *Compiler {
	return &Compiler{internalSuffixes: slices.Clone(internalSuffixes), changed: map[string]bool{}, wake: make(chan struct{}, 1)}
}

// SetupWithManager reads profiles from the manager's cache and watches them.
func (c *Compiler) SetupWithManager(mgr manager.Manager) error {
	ctx := context.Background()
	namespaces, err := mgr.GetCache().GetInformer(ctx, &corev1.Namespace{})
	if err != nil {
		return fmt.Errorf("watch namespaces: %w", err)
	}
	if _, err := namespaces.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if namespace, ok := obj.(*corev1.Namespace); ok && controlled(namespace) {
				c.notify(namespace.Name)
			}
		},
		UpdateFunc: func(old, obj any) {
			before, ok1 := old.(*corev1.Namespace)
			after, ok2 := obj.(*corev1.Namespace)
			if ok1 && ok2 && controlled(before) != controlled(after) {
				c.notify(after.Name)
			}
		},
	}); err != nil {
		return err
	}
	entries := &unstructured.Unstructured{}
	entries.SetGroupVersionKind(ServiceEntryGVK)
	informer, err := mgr.GetCache().GetInformer(ctx, entries)
	if err != nil {
		return fmt.Errorf("watch ServiceEntries: %w", err)
	}
	onEntry := func(obj any) {
		if tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			obj = tombstone.Obj
		}
		if entry, ok := obj.(client.Object); ok && profileEntry(entry) {
			c.notify(entry.GetNamespace())
		}
	}
	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc:    onEntry,
		UpdateFunc: func(old, obj any) { onEntry(old); onEntry(obj) },
		DeleteFunc: onEntry,
	}); err != nil {
		return err
	}
	c.mu.Lock()
	c.reader = mgr.GetCache()
	c.mu.Unlock()
	return nil
}

// Compile limits policy to the Atespace's profile, if it has one.
func (c *Compiler) Compile(ctx context.Context, input egresspolicy.Input, policy *ateapipb.EgressPolicy) error {
	profile, ok, err := c.Profile(ctx, input.Atespace)
	if err != nil {
		return err
	}
	if ok {
		Limit(policy, profile, c.internalSuffixes)
	}
	return nil
}

// Changed blocks until a namespace's profile may have changed and returns the
// changed Atespaces.
func (c *Compiler) Changed(ctx context.Context) ([]string, error) {
	for {
		c.mu.Lock()
		if len(c.changed) != 0 {
			changed := make([]string, 0, len(c.changed))
			for atespace := range c.changed {
				changed = append(changed, atespace)
			}
			clear(c.changed)
			c.mu.Unlock()
			slices.Sort(changed)
			return changed, nil
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.wake:
		}
	}
}

func (c *Compiler) notify(atespace string) {
	c.mu.Lock()
	c.changed[atespace] = true
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Profile reads the profile of namespace. ok is false when it has none.
func (c *Compiler) Profile(ctx context.Context, namespace string) (Profile, bool, error) {
	c.mu.Lock()
	reader := c.reader
	c.mu.Unlock()
	if reader == nil {
		return Profile{}, false, fmt.Errorf("workspace egress profiles are not loaded yet")
	}
	ns := &corev1.Namespace{}
	if err := reader.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
		return Profile{}, false, fmt.Errorf("read namespace %s for its egress profile: %w", namespace, err)
	}
	if !controlled(ns) {
		return Profile{}, false, nil
	}
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(ServiceEntryGVK.GroupVersion().WithKind(ServiceEntryGVK.Kind + "List"))
	if err := reader.List(ctx, list, client.InNamespace(namespace), client.MatchingLabelsSelector{Selector: serviceEntrySelector}); err != nil {
		return Profile{}, false, fmt.Errorf("read egress profile of %s: %w", namespace, err)
	}
	var profile Profile
	for i := range list.Items {
		if profileEntry(&list.Items[i]) {
			profile.Destinations = append(profile.Destinations, Destinations(&list.Items[i])...)
		}
	}
	return profile, true, nil
}

func controlled(namespace *corev1.Namespace) bool {
	return namespace.Labels[NamespaceLabel] == NamespaceLabelValue
}

func profileEntry(entry client.Object) bool {
	_, ok := entry.GetLabels()[ProfileLabel]
	return ok && serviceEntrySelector.Matches(labels.Set(entry.GetLabels()))
}

// Destinations maps a ServiceEntry's hosts and ports to profile destinations.
// TLS and HTTPS ports grant HTTPS; HTTP ports grant HTTP. Other protocols have
// no actor rule and grant nothing.
func Destinations(entry *unstructured.Unstructured) []Destination {
	hosts, _, _ := unstructured.NestedStringSlice(entry.Object, "spec", "hosts")
	ports, _, _ := unstructured.NestedSlice(entry.Object, "spec", "ports")
	var destinations []Destination
	for _, raw := range ports {
		port, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		number, ok := port["number"].(int64)
		if !ok || number < 1 || number > 65535 {
			continue
		}
		protocol, _ := port["protocol"].(string)
		var kind string
		switch strings.ToUpper(protocol) {
		case "TLS", "HTTPS":
			kind = KindHTTPS
		case "HTTP":
			kind = KindHTTP
		default:
			continue
		}
		for _, host := range hosts {
			destinations = append(destinations, Destination{Host: strings.ToLower(host), Port: int32(number), Kind: kind})
		}
	}
	return destinations
}
