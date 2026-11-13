// Package egresspolicy lets an embedding controller extend actor EgressPolicies.
package egresspolicy

import (
	"context"

	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
)

// GatewayTarget is the header a tokenPassthrough client sends the caller's
// token in. Origins are canonical (https://host:443) and headers lowercase.
type GatewayTarget struct {
	Origin string `json:"origin"`
	Header string `json:"header"`
	Prefix string `json:"prefix,omitempty"`
}

// Input is the persisted state a Compiler reads for one actor.
type Input struct {
	Atespace       string
	GatewayTargets []GatewayTarget
}

// Compiler extends the built-in policy and may change anything in it. Compilers
// run in order; afterwards every target must have a header on its origin.
// Compile may run more than once per actor and must not have side effects.
type Compiler interface {
	Compile(context.Context, Input, *ateapipb.EgressPolicy) error
}

// Watcher is implemented by a Compiler whose output depends on state outside
// kagent. Changed blocks until that state may have changed and returns the
// affected Atespaces; the elected controller then reapplies the policy of every
// allocated actor in them. Changed must not lose a change while nobody calls it.
type Watcher interface {
	Changed(context.Context) ([]string, error)
}
