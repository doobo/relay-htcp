package tunnel

import (
	"context"
	"time"

	"relay-htcp/internal/admin"
)

// Token traffic quotas.
//
// Configuration carries per-token daily/weekly/monthly limits (MB) and an
// enable switch. A background task re-evaluates every token against the daily
// traffic table (default every 5 minutes, tunnel.quota_refresh). The resulting
// blocked set is published atomically, so the request path only performs one
// cached map lookup and never touches the database.
//
// Counters are accumulated in memory and flushed in batches, so a refresh may
// see totals a few seconds stale. That is intentional: limits are enforced on
// a coarse schedule, not per byte.

// startQuotaLoop launches the periodic re-evaluation task (idempotent).
func (s *Server) startQuotaLoop(ctx context.Context) {
	s.quotaRun.Do(func() {
		go func() {
			s.refreshTokenLimits()
			for {
				iv := s.cfgGet().Tunnel.QuotaRefresh
				if iv <= 0 {
					iv = 5 * time.Minute
				}
				timer := time.NewTimer(iv)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
					s.refreshTokenLimits()
				}
			}
		}()
	})
}

// refreshTokenLimits recomputes the blocked set from the daily traffic table.
func (s *Server) refreshTokenLimits() {
	tokens := s.tokens.Load()
	if tokens == nil {
		return
	}
	traffic := s.trafficStats()
	now := time.Now()
	next := make(map[string]bool)
	if traffic != nil {
		dayStart := admin.PeriodStartDay("day", now)
		weekStart := admin.PeriodStartDay("week", now)
		monthStart := admin.PeriodStartDay("month", now)
		today := admin.DayString(now)
		for i := range *tokens {
			entry := &(*tokens)[i]
			if !entry.limitEnabled || entry.statsKey == "" {
				continue
			}
			if exceedsLimit(traffic, entry, dayStart, weekStart, monthStart, today) {
				next[entry.statsKey] = true
			}
		}
	}
	prev := s.blocked.Load()
	s.blocked.Store(&next)
	if s.log != nil {
		for key := range next {
			if prev == nil || !(*prev)[key] {
				s.log.Warn("token traffic limit reached, token blocked", "token", key)
			}
		}
		if prev != nil {
			for key := range *prev {
				if !next[key] {
					s.log.Info("token traffic limit no longer exceeded, unblocked", "token", key)
				}
			}
		}
	}
}

func exceedsLimit(t *admin.TrafficStats, entry *tokenEntry,
	dayStart, weekStart, monthStart, today string) bool {
	for _, period := range []struct {
		limit int64
		from  string
	}{
		{entry.dailyLimit, dayStart},
		{entry.weeklyLimit, weekStart},
		{entry.monthlyLimit, monthStart},
	} {
		if period.limit <= 0 {
			continue
		}
		in, out, err := t.Usage(admin.TrafficScopeServer, entry.statsKey, period.from, today)
		if err != nil {
			continue
		}
		if in+out >= period.limit {
			return true
		}
	}
	return false
}
