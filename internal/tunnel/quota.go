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
	set := s.tokens.Load()
	if set == nil {
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
		totals, err := traffic.PeriodTotals(admin.TrafficScopeServer, dayStart, weekStart, monthStart, today)
		if err != nil {
			if s.log != nil {
				s.log.Warn("token quota refresh failed, keeping previous state", "err", err)
			}
			return
		}
		for i := range set.list {
			entry := &set.list[i]
			if !entry.limitEnabled || entry.statsKey == "" {
				continue
			}
			if exceedsLimit(totals[entry.statsKey], entry) {
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

func exceedsLimit(totals admin.PeriodTotals, entry *tokenEntry) bool {
	return (entry.dailyLimit > 0 && totals.Day >= entry.dailyLimit) ||
		(entry.weeklyLimit > 0 && totals.Week >= entry.weeklyLimit) ||
		(entry.monthlyLimit > 0 && totals.Month >= entry.monthlyLimit)
}
