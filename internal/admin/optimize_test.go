package admin

import (
	"testing"
	"time"
)

func TestPeriodTotalsAcrossBoundaries(t *testing.T) {
	tr := openTrafficTest(t)
	// 2026-02-01 is a Sunday; with Monday-based weeks the week starts on
	// 2026-01-26, which is in the previous month.
	now := time.Date(2026, 2, 1, 9, 0, 0, 0, time.Local)
	tr.now = func() time.Time { return now }
	tr.Record(TrafficScopeServer, "a", "", "ssh", 1, 1)
	tr.Record(TrafficScopeServer, "a", "", "ssh", 1, 1)
	tr.now = func() time.Time { return time.Date(2026, 1, 28, 9, 0, 0, 0, time.Local) }
	tr.Record(TrafficScopeServer, "a", "", "ssh", 10, 10)
	tr.now = func() time.Time { return time.Date(2026, 1, 3, 9, 0, 0, 0, time.Local) }
	tr.Record(TrafficScopeServer, "a", "", "ssh", 100, 100)

	today := DayString(now)
	totals, err := tr.PeriodTotals(TrafficScopeServer,
		PeriodStartDay("day", now), PeriodStartDay("week", now), PeriodStartDay("month", now), today)
	if err != nil {
		t.Fatal(err)
	}
	got := totals["a"]
	if got.Day != 4 || got.Week != 24 || got.Month != 4 {
		t.Fatalf("totals = %+v, want day=4 week=24 month=4", got)
	}
}

func TestGetSessionUserRejectsDisabledUser(t *testing.T) {
	store := openTestStore(t)
	u, err := store.CreateUser("alice", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession("sess-hash", u.ID, int64(time.Hour/time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetSessionUser("sess-hash")
	if err != nil || got.ID != u.ID || got.Username != "alice" {
		t.Fatalf("GetSessionUser = %+v, %v", got, err)
	}
	if err := store.UpdateUserEnabled(u.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSessionUser("sess-hash"); err != ErrNotFound {
		t.Fatalf("disabled user err = %v, want ErrNotFound", err)
	}
	if _, err := store.GetSessionUser("missing"); err != ErrNotFound {
		t.Fatalf("unknown session err = %v, want ErrNotFound", err)
	}
}
