package admin

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func openTrafficTest(t *testing.T) *TrafficStats {
	t.Helper()
	store := openTestStore(t)
	return NewTrafficStats(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestTrafficStatsRecordFlushAndQuery(t *testing.T) {
	tr := openTrafficTest(t)
	fixed := time.Date(2026, 1, 5, 12, 0, 0, 0, time.Local) // Monday
	tr.now = func() time.Time { return fixed }
	day := DayString(fixed)

	tr.Record(TrafficScopeServer, "tok-a", "", "ssh", 100, 200)
	tr.Record(TrafficScopeServer, "tok-a", "", "ssh", 10, 20)
	tr.Record(TrafficScopeServer, "tok-b", "", "mysql", 5, 6)
	tr.Record(TrafficScopeClient, "", "primary", "ssh", 7, 8)

	rows, err := tr.DailyRows(TrafficScopeServer, day, "", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Token != "tok-a" || rows[0].BytesIn != 110 || rows[0].BytesOut != 220 {
		t.Fatalf("top row = %+v", rows[0])
	}
	if rows[1].Token != "tok-b" || rows[1].Route != "mysql" {
		t.Fatalf("second row = %+v", rows[1])
	}

	in, out, err := tr.Usage(TrafficScopeServer, "tok-a", day, day)
	if err != nil {
		t.Fatal(err)
	}
	if in != 110 || out != 220 {
		t.Fatalf("usage = %d/%d", in, out)
	}

	clientRows, err := tr.DailyRows(TrafficScopeClient, day, "", "primary", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(clientRows) != 1 || clientRows[0].Route != "ssh" || clientRows[0].BytesIn != 7 {
		t.Fatalf("client rows = %+v", clientRows)
	}

	// A second flush accumulates instead of replacing.
	tr.Record(TrafficScopeServer, "tok-a", "", "ssh", 1, 2)
	in, out, _ = tr.Usage(TrafficScopeServer, "tok-a", day, day)
	if in != 111 || out != 222 {
		t.Fatalf("usage after second flush = %d/%d", in, out)
	}
}

func TestTrafficFiltersAndSinceRows(t *testing.T) {
	tr := openTrafficTest(t)
	tr.now = func() time.Time { return time.Date(2026, 2, 10, 9, 0, 0, 0, time.Local) }
	tr.Record(TrafficScopeServer, "a", "", "ssh", 10, 0)
	tr.Record(TrafficScopeServer, "b", "", "ssh", 20, 0)

	rows, err := tr.DailyRows(TrafficScopeServer, "2026-02-10", "a", "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Token != "a" {
		t.Fatalf("filtered rows = %+v", rows)
	}

	since, err := tr.RowsSince(TrafficScopeServer, "", "", "2026-02-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(since) != 2 {
		t.Fatalf("since rows = %+v", since)
	}
}

func TestPeriodStartDay(t *testing.T) {
	// 2026-02-11 is a Wednesday.
	now := time.Date(2026, 2, 11, 15, 4, 5, 0, time.Local)
	if got := PeriodStartDay("day", now); got != "2026-02-11" {
		t.Fatalf("day = %q", got)
	}
	if got := PeriodStartDay("week", now); got != "2026-02-09" {
		t.Fatalf("week = %q", got)
	}
	if got := PeriodStartDay("month", now); got != "2026-02-01" {
		t.Fatalf("month = %q", got)
	}
}

func TestTokenStatsKey(t *testing.T) {
	a := TokenStatsKey("secret-a")
	b := TokenStatsKey("secret-b")
	if a == b || a == "" || !strings.HasPrefix(a, "tk-") {
		t.Fatalf("digest keys = %q %q", a, b)
	}
	if a != TokenStatsKey("secret-a") {
		t.Fatal("stats key is not stable")
	}
}
