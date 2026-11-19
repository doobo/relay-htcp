package admin

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TokenBlockProvider is implemented by a role that enforces per-token quota
// limits. The admin package only reads the runtime blocked cache; it never
// queries the database on the request path.
type TokenBlockProvider interface {
	TokenBlocked(statsKey string) bool
}

// trafficFilter is one option of the status page's token/server filter.
type trafficFilter struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type trafficUsage struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

type dailyTrafficResponse struct {
	Scope      string          `json:"scope"`
	Day        string          `json:"day"`
	FilterKind string          `json:"filter_kind"`
	Filters    []trafficFilter `json:"filters"`
	Rows       []TrafficRow    `json:"rows"`
	Limit      int             `json:"limit"`
}

type tokenTrafficResponse struct {
	Token   clientTokenView         `json:"token"`
	Days    int                     `json:"days"`
	Rows    []TrafficRow            `json:"rows"`
	Usage   map[string]trafficUsage `json:"usage"`
	Blocked bool                    `json:"blocked"`
}

// handleDailyTraffic backs the status page traffic table. It returns the most
// recent daily rows (today by default), capped at the requested limit.
func (a *Server) handleDailyTraffic(w http.ResponseWriter, r *http.Request) {
	scope := TrafficScopeClient
	filterKind := "server"
	if a.provider.Role() == "server" {
		scope = TrafficScopeServer
		filterKind = "token"
	}
	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	filters := trafficFilters(scope, doc)

	day := strings.TrimSpace(r.URL.Query().Get("day"))
	if day == "" {
		day = DayString(time.Now())
	}
	limit := 20
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200
	}
	token := ""
	server := ""
	if scope == TrafficScopeServer {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	} else {
		server = strings.TrimSpace(r.URL.Query().Get("server"))
	}
	rows, err := a.traffic.DailyRows(scope, day, token, server, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, dailyTrafficResponse{
		Scope: scope, Day: day, FilterKind: filterKind,
		Filters: filters, Rows: rows, Limit: limit,
	})
}

// handleTokenTraffic returns the daily rows and period totals for one token.
// It is the "详细" action on the token page.
func (a *Server) handleTokenTraffic(w http.ResponseWriter, r *http.Request) {
	if !a.requireServerRole(w) {
		return
	}
	index, err := strconv.Atoi(r.PathValue("index"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid token index")
		return
	}
	doc, err := parseConfigDoc(a.provider.CurrentConfigYAML())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := listTokenViews(doc)
	if index < 0 || index >= len(views) {
		writeError(w, http.StatusNotFound, "token not found")
		return
	}
	view := views[index]
	days := 14
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			days = n
		}
	}
	if days > 90 {
		days = 90
	}
	now := time.Now()
	rows, err := a.traffic.RowsSince(TrafficScopeServer, view.StatsKey, "",
		DayString(now.AddDate(0, 0, -(days-1))), 0)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	usage := map[string]trafficUsage{}
	for _, period := range []string{"day", "week", "month"} {
		from := PeriodStartDay(period, now)
		in, out, err := a.traffic.Usage(TrafficScopeServer, view.StatsKey, from, DayString(now))
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		usage[period] = trafficUsage{BytesIn: in, BytesOut: out}
	}
	blocked := false
	if p, ok := a.provider.(TokenBlockProvider); ok {
		blocked = p.TokenBlocked(view.StatsKey)
	}
	writeJSON(w, http.StatusOK, tokenTrafficResponse{
		Token: view, Days: days, Rows: rows, Usage: usage, Blocked: blocked,
	})
}

// trafficFilters builds the filter options for the status page.
func trafficFilters(scope string, doc map[string]any) []trafficFilter {
	out := []trafficFilter{}
	if scope == TrafficScopeServer {
		for _, v := range listTokenViews(doc) {
			label := v.Name
			if label == "" {
				label = "（未命名）" + v.TokenHint
			}
			out = append(out, trafficFilter{Key: v.StatsKey, Label: label})
		}
		return out
	}
	if raw, ok := lookupPath(doc, "servers"); ok {
		if rows, ok := raw.([]any); ok {
			for _, item := range rows {
				row, _ := item.(map[string]any)
				name := strings.TrimSpace(asString(row["name"]))
				if name == "" {
					continue
				}
				out = append(out, trafficFilter{Key: name, Label: name})
			}
		}
	}
	return out
}
