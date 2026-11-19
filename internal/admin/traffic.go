package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"
)

// Traffic statistics.
//
// Both roles accumulate byte counters in memory first (Record) and flushed
// batches are upserted into traffic_daily at a fixed interval. Losing the
// last few seconds of counters on a crash is deliberate: the write path must
// never slow a tunnel stream down, and daily totals are informational.
//
// The same table backs both roles:
//   - server scope: token = client token identity, route = server route;
//   - client scope: server = configured server name, route = target route.
const (
	// TrafficScopeServer is the server-side (per client token) scope.
	TrafficScopeServer = "server"
	// TrafficScopeClient is the client-side (per server route) scope.
	TrafficScopeClient = "client"

	trafficFlushInterval = 30 * time.Second
)

// TrafficRow is one aggregated daily traffic row.
type TrafficRow struct {
	Day      string `json:"day"`
	Token    string `json:"token,omitempty"`
	Server   string `json:"server,omitempty"`
	Route    string `json:"route,omitempty"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// trafficKey identifies one daily accumulator bucket.
type trafficKey struct {
	scope  string
	token  string
	server string
	route  string
	day    string
}

// TrafficStats owns the in-memory counters and the periodic flush task.
type TrafficStats struct {
	store *Store
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	pending map[trafficKey]*TrafficRow

	startOnce sync.Once
}

// NewTrafficStats builds a recorder on top of store. Start it with Start to
// enable periodic flushing; Flush can also be called manually.
func NewTrafficStats(store *Store, log *slog.Logger) *TrafficStats {
	return &TrafficStats{
		store:   store,
		log:     log,
		now:     time.Now,
		pending: make(map[trafficKey]*TrafficRow),
	}
}

// TokenStatsKey is the stable per-token key used by traffic rows. It is a
// short digest of the secret, never the display name: renaming a token keeps
// its history and duplicate names cannot merge unrelated counters.
func TokenStatsKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "tk-" + hex.EncodeToString(sum[:8])
}

// Record adds in/out bytes to the current day's bucket. It is cheap and safe
// to call on the stream hot path.
func (t *TrafficStats) Record(scope, token, server, route string, in, out int64) {
	if t == nil || (in == 0 && out == 0) {
		return
	}
	key := trafficKey{
		scope: scope, token: token, server: server, route: route,
		day: t.now().Format("2006-01-02"),
	}
	t.mu.Lock()
	row := t.pending[key]
	if row == nil {
		row = &TrafficRow{Day: key.day, Token: token, Server: server, Route: route}
		t.pending[key] = row
	}
	row.BytesIn += in
	row.BytesOut += out
	t.mu.Unlock()
}

// Start launches the periodic flush task. It is idempotent and stops with ctx,
// flushing any remaining counters on the way out.
func (t *TrafficStats) Start(ctx context.Context) {
	if t == nil {
		return
	}
	t.startOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(trafficFlushInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					_ = t.Flush()
					return
				case <-ticker.C:
					_ = t.Flush()
				}
			}
		}()
	})
}

// Flush writes the accumulated counters to the database. A failed batch is
// merged back so a transient lock does not discard it. Concurrent Record
// calls are never blocked by the database write.
func (t *TrafficStats) Flush() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	if len(t.pending) == 0 {
		t.mu.Unlock()
		return nil
	}
	batch := t.pending
	t.pending = make(map[trafficKey]*TrafficRow)
	t.mu.Unlock()

	err := t.store.Transaction(func(tx *sql.Tx) error {
		now := nowMs()
		for key, row := range batch {
			_, err := tx.Exec(
				`INSERT INTO traffic_daily
					(scope, token, server, route, day, bytes_in, bytes_out, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				 ON CONFLICT(scope, token, server, route, day) DO UPDATE SET
					bytes_in = traffic_daily.bytes_in + excluded.bytes_in,
					bytes_out = traffic_daily.bytes_out + excluded.bytes_out,
					updated_at = excluded.updated_at`,
				key.scope, key.token, key.server, key.route, key.day,
				row.BytesIn, row.BytesOut, now)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.mu.Lock()
		for key, row := range batch {
			if cur := t.pending[key]; cur != nil {
				cur.BytesIn += row.BytesIn
				cur.BytesOut += row.BytesOut
				continue
			}
			t.pending[key] = row
		}
		t.mu.Unlock()
		if t.log != nil {
			t.log.Warn("traffic flush failed, kept counters in memory", "rows", len(batch), "err", err)
		}
	}
	return err
}

// DailyRows returns today's (or any day's) aggregated rows, ordered by total
// bytes descending. token/server are optional filters. It flushes first so
// totals shown in the panel include counters not yet written by the ticker.
func (t *TrafficStats) DailyRows(scope, day, token, server string, limit int) ([]TrafficRow, error) {
	if t == nil {
		return nil, nil
	}
	_ = t.Flush()
	query := `SELECT day, token, server, route,
			SUM(bytes_in), SUM(bytes_out)
		FROM traffic_daily
		WHERE scope = ? AND day = ?`
	args := []any{scope, day}
	if token != "" {
		query += ` AND token = ?`
		args = append(args, token)
	}
	if server != "" {
		query += ` AND server = ?`
		args = append(args, server)
	}
	query += ` GROUP BY day, token, server, route
		ORDER BY SUM(bytes_in) + SUM(bytes_out) DESC, token, server, route`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	return t.queryRows(query, args...)
}

// RowsSince returns per-day, per-route rows starting at fromDay (inclusive).
func (t *TrafficStats) RowsSince(scope, token, server, fromDay string, limit int) ([]TrafficRow, error) {
	if t == nil {
		return nil, nil
	}
	_ = t.Flush()
	query := `SELECT day, token, server, route,
			SUM(bytes_in), SUM(bytes_out)
		FROM traffic_daily
		WHERE scope = ? AND day >= ?`
	args := []any{scope, fromDay}
	if token != "" {
		query += ` AND token = ?`
		args = append(args, token)
	}
	if server != "" {
		query += ` AND server = ?`
		args = append(args, server)
	}
	query += ` GROUP BY day, token, server, route
		ORDER BY day DESC, SUM(bytes_in) + SUM(bytes_out) DESC`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	return t.queryRows(query, args...)
}

// Usage sums in/out bytes for one token between fromDay and toDay inclusive.
func (t *TrafficStats) Usage(scope, token, fromDay, toDay string) (in, out int64, err error) {
	if t == nil {
		return 0, 0, nil
	}
	_ = t.Flush()
	err = t.store.Read().QueryRow(
		`SELECT COALESCE(SUM(bytes_in), 0), COALESCE(SUM(bytes_out), 0)
		 FROM traffic_daily
		 WHERE scope = ? AND token = ? AND day >= ? AND day <= ?`,
		scope, token, fromDay, toDay).Scan(&in, &out)
	return in, out, err
}

func (t *TrafficStats) queryRows(query string, args ...any) ([]TrafficRow, error) {
	rows, err := t.store.Read().Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficRow{}
	for rows.Next() {
		var row TrafficRow
		if err := rows.Scan(&row.Day, &row.Token, &row.Server, &row.Route,
			&row.BytesIn, &row.BytesOut); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// DayString formats a time as a traffic day key.
func DayString(t time.Time) string { return t.Format("2006-01-02") }

// PeriodStartDay returns the first day of the current day/week/month period.
// Weeks start on Monday.
func PeriodStartDay(period string, now time.Time) string {
	switch period {
	case "week":
		offset := (int(now.Weekday()) + 6) % 7 // Monday = 0
		return DayString(now.AddDate(0, 0, -offset))
	case "month":
		return DayString(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()))
	default:
		return DayString(now)
	}
}
