package controller

import (
	"context"
	"errors"
	"time"

	"github.com/kagent-dev/kagent/go/core/pkg/egresspolicy"
	"github.com/kagent-dev/kagent/go/pkg/logging"
)

// EgressRefresher reapplies actor policies in the Atespaces a Watcher reports.
// Failed Atespaces retry with exponential backoff. Changes reported while
// another replica leads are covered by the startup replay of every source.
type EgressRefresher struct {
	store      atespaceEgressStore
	actors     actorEgressClient
	watcher    egresspolicy.Watcher
	minBackoff time.Duration
	maxBackoff time.Duration
}

// NewEgressRefresher returns a leader-elected EgressRefresher.
func NewEgressRefresher(store atespaceEgressStore, actors actorEgressClient, watcher egresspolicy.Watcher) *EgressRefresher {
	return &EgressRefresher{store: store, actors: actors, watcher: watcher, minBackoff: time.Second, maxBackoff: 5 * time.Minute}
}

// NeedLeaderElection keeps Substrate writes on the elected controller.
func (r *EgressRefresher) NeedLeaderElection() bool { return true }

// Start runs until ctx is cancelled.
func (r *EgressRefresher) Start(ctx context.Context) error {
	changes := make(chan []string)
	go func() {
		for {
			changed, err := r.watcher.Changed(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logging.FromContext(ctx).ErrorContext(ctx, "egress policy watcher stopped", "error", err)
				}
				return
			}
			select {
			case changes <- changed:
			case <-ctx.Done():
				return
			}
		}
	}()
	type retry struct {
		at      time.Time
		backoff time.Duration
	}
	pending := map[string]retry{}
	for {
		var timer *time.Timer
		var next <-chan time.Time
		if len(pending) != 0 {
			earliest := time.Time{}
			for _, state := range pending {
				if earliest.IsZero() || state.at.Before(earliest) {
					earliest = state.at
				}
			}
			timer = time.NewTimer(time.Until(earliest))
			next = timer.C
		}
		select {
		case <-ctx.Done():
			return nil
		case changed := <-changes:
			for _, atespace := range changed {
				pending[atespace] = retry{at: time.Now(), backoff: pending[atespace].backoff}
			}
		case <-next:
		}
		if timer != nil {
			timer.Stop()
		}
		now := time.Now()
		for atespace, state := range pending {
			if state.at.After(now) {
				continue
			}
			err := applyAtespaceEgress(ctx, r.store, r.actors, atespace)
			if err == nil {
				delete(pending, atespace)
				continue
			}
			if errors.Is(err, context.Canceled) && ctx.Err() != nil {
				return nil
			}
			backoff := min(max(2*state.backoff, r.minBackoff), r.maxBackoff)
			pending[atespace] = retry{at: time.Now().Add(backoff), backoff: backoff}
			logging.FromContext(ctx).ErrorContext(ctx, "failed to reapply actor egress after a policy input changed", "atespace", atespace, "retry_in", backoff, "error", err)
		}
	}
}
