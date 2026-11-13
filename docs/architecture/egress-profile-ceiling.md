# Workspace egress profile ceiling

A cluster can assign each namespace a workspace egress profile: an allowlist of
external hosts and ports, rendered as Istio resources. Agents and sandboxes are
Substrate actors without a sidecar, so those resources do not apply to them.
The ceiling is an `egresspolicy.Compiler` that applies the same profile to
actor EgressPolicies. It is off by default.

```yaml
controller:
  env:
    - name: KAGENT_EGRESS_PROFILE_CEILING
      value: "true"
```

## Semantics

- A namespace without the label `prokube.ai/egress-control=enabled` has no
  ceiling. Its actors keep the policy kagent compiles.
- In a labelled namespace, each actor in the namespace's Atespace gets at most
  what the profile allows: effective access is the actor's policy intersected
  with the profile. A profile without destinations allows no external access.
- The ceiling only removes access. EgressPolicies, inferred model and MCP
  destinations and credentials are unchanged for destinations the profile allows.
- It applies to Agent sessions and to sandboxes, including sandboxes an Agent
  starts through the kagent tools: both pass the compiler chain on create,
  resume and every policy update.

## The profile

The profile is read from the namespace:

| Resource | Meaning |
| --- | --- |
| Namespace label `prokube.ai/egress-control=enabled` | A profile is assigned. |
| `ServiceEntry` (`networking.istio.io/v1beta1`) with labels `prokube.ai/managed-by=pkui` and `prokube.ai/egress-profile` | Allowed hosts × ports. |

Other ServiceEntries do not widen the ceiling. The writer must keep users from
creating ServiceEntries with these labels or editing the namespace label.

Each host and port maps to an actor rule:

| ServiceEntry port protocol | Allows |
| --- | --- |
| `TLS`, `HTTPS` | `https://host:port` and TLS passthrough to it |
| `HTTP` | `http://host:port` |
| `TCP` and others | nothing (actor policies have no raw TCP) |

Hosts are exact DNS names or one leading wildcard label. A profile wildcard
`*.example.com` allows `a.example.com` and `*.example.com`, not `example.com` or
`a.b.example.com`. An actor wildcard the profile does not cover narrows to the
profile's exact hosts it matches. A rule for every port narrows to the profile's
ports. Credential effects stay on rules the profile allows unchanged.

## Internal destinations

Kubernetes Service names are exempt: hostnames ending in `.svc.cluster.local`
or `.svc`. This keeps the runtime control plane, models and MCP servers behind
an in-cluster gateway, OTLP collectors and other Services reachable. Set
`KAGENT_EGRESS_PROFILE_INTERNAL_SUFFIXES` (comma-separated) for another cluster
domain. A Service that forwards to the internet (a proxy or gateway) is governed
by that Service, not by the ceiling. Actor policies reject IP addresses, so
there is no IP-based internal access.

## Updates

The compiler watches labelled Namespaces and the profile ServiceEntries. A
change marks the namespace's Atespace, and the elected controller reapplies the
policy of every allocated actor there, including suspended actors, without
restarting them. Failures retry with exponential backoff (1s to 5m). Changes
while another replica leads are covered by the startup replay of every source.

## Failure behavior

The ceiling fails closed. If the namespace or ServiceEntries cannot be read,
creation and resume stop, and an update applies a deny-all policy and retries.
An Atespace whose namespace no longer exists counts as unreadable.

## Limits

- With any compiler registered, kagent requires compilers to bind every
  `tokenPassthrough` target. The ceiling binds none, so Agents with a
  `tokenPassthrough` model or MCP server cannot start while it is enabled, in
  any namespace.
- The ceiling reads the profile writer's resources, not the profile itself.
  Profiles in other formats need another reader.
- Golden actor preparation uses its own bootstrap policy, which only reaches
  the control plane.
