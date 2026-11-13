package controller

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kagent-dev/kagent/go/core/internal/database"
)

type atespaceTargetStoreStub struct {
	targets map[string][]database.RuntimeEgressTarget
}

func (s *atespaceTargetStoreStub) ListRuntimeEgressAtespaceTargets(_ context.Context, atespace, after string, limit int) ([]database.RuntimeEgressTarget, error) {
	targets := slices.DeleteFunc(slices.Clone(s.targets[atespace]), func(target database.RuntimeEgressTarget) bool { return target.ID <= after })
	return targets[:min(len(targets), limit)], nil
}

type watcherStub chan []string

func (w watcherStub) Changed(ctx context.Context) ([]string, error) {
	select {
	case changed := <-w:
		return changed, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestEgressRefresherReappliesChangedAtespacesAndRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &atespaceTargetStoreStub{targets: map[string][]database.RuntimeEgressTarget{
			"team":  {{ID: "1", Revision: "r", Atespace: "team", TemplateName: "runtime"}, {ID: "2", Revision: "r", Atespace: "team", TemplateName: "runtime"}},
			"other": {{ID: "3", Revision: "r", Atespace: "other", TemplateName: "runtime"}},
		}}
		var mu sync.Mutex
		applied := map[string][]time.Time{}
		failures := 2
		actors := &actorEgressStub{ensurePolicy: func(_ context.Context, atespace, name, _ string) error {
			mu.Lock()
			defer mu.Unlock()
			applied[atespace+"/"+name] = append(applied[atespace+"/"+name], time.Now())
			if name == "session-1" && failures > 0 {
				failures--
				return errors.New("backend unavailable")
			}
			return nil
		}}
		watcher := make(watcherStub)
		refresher := NewEgressRefresher(store, actors, watcher)
		require.True(t, refresher.NeedLeaderElection())
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error)
		go func() { done <- refresher.Start(ctx) }()

		start := time.Now()
		watcher <- []string{"team"}
		synctest.Wait()
		time.Sleep(time.Hour)
		synctest.Wait()
		mu.Lock()
		require.Len(t, applied["team/session-1"], 3, "the failing actor retries until it succeeds")
		require.Equal(t, []time.Duration{0, time.Second, 3 * time.Second}, []time.Duration{
			applied["team/session-1"][0].Sub(start), applied["team/session-1"][1].Sub(start), applied["team/session-1"][2].Sub(start),
		})
		require.Len(t, applied["team/session-2"], 3, "a retry reapplies the whole Atespace")
		require.Empty(t, applied["other/session-3"])
		mu.Unlock()

		watcher <- []string{"other"}
		synctest.Wait()
		mu.Lock()
		require.Len(t, applied["other/session-3"], 1)
		mu.Unlock()
		cancel()
		require.NoError(t, <-done)
	})
}
