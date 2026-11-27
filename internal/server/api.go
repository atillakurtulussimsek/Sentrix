package server

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type apiHost struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname"`
	Status         string    `json:"status"`
	OS             string    `json:"os"`
	LastSeen       time.Time `json:"last_seen"`
	Group          string    `json:"group"`
	Tags           []string  `json:"tags"`
	CPU            *float64  `json:"cpu_pct,omitempty"`
	Mem            *float64  `json:"mem_pct,omitempty"`
	Disk           *float64  `json:"disk_pct,omitempty"`
	RebootRequired bool      `json:"reboot_required"`
	Updates        int       `json:"updates"`
	SecUpdates     int       `json:"security_updates"`
	Risk           float64   `json:"risk"`
	Critical       int       `json:"critical"`
	KEV            int       `json:"kev"`
}

func optF(f float64) *float64 {
	if f < 0 {
		return nil
	}
	return &f
}

func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	sums, err := s.summaries(r)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "internal error"})
		return
	}
	out := make([]apiHost, 0, len(sums))
	for _, h := range sums {
		out = append(out, apiHost{h.ID, h.Hostname, h.Status, h.OS, h.LastSeen, h.Group, h.Tags, optF(h.CPU), optF(h.Mem), optF(h.Disk),
			h.RebootRequired, h.Updates, h.SecUpdates, h.Risk, h.Critical, h.KEV})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	writeJSON(w, 200, map[string]string{"username": a.User.Username, "role": a.Role, "via": a.Via})
}

type alignedSeries struct {
	Key    string     `json:"key"`
	Values []*float64 `json:"values"`
}

// apiSeries returns several metrics of a host aligned on a common time axis (for uPlot).
func (s *Server) apiSeries(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q := r.URL.Query()
	rangeSec, _ := strconv.Atoi(q.Get("range"))
	if rangeSec <= 0 || rangeSec > 90*86400 {
		rangeSec = 3600
	}
	now := time.Now()
	from := now.Add(-time.Duration(rangeSec) * time.Second)
	allLabels := q.Get("labels") == "all"
	tsSet := map[int64]struct{}{}
	type keyed struct {
		key string
		pts map[int64]float64
	}
	var series []keyed
	for _, name := range strings.Split(q.Get("metrics"), ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		mq := store.MetricQuery{HostID: id, Name: name, From: from, To: now, Resolution: q.Get("resolution")}
		if !allLabels {
			empty := ""
			mq.Labels = &empty
		}
		res, err := s.mets.Query(r.Context(), mq)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		for _, sr := range res {
			k := keyed{key: store.SeriesKey(sr.Name, sr.Labels), pts: map[int64]float64{}}
			for _, p := range sr.Points {
				k.pts[p.TS] = p.Value
				tsSet[p.TS] = struct{}{}
			}
			series = append(series, k)
		}
		if len(series) > 24 {
			break
		}
	}
	ts := make([]int64, 0, len(tsSet))
	for t := range tsSet {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	out := struct {
		Timestamps []int64         `json:"timestamps"`
		Series     []alignedSeries `json:"series"`
	}{Timestamps: ts, Series: []alignedSeries{}}
	for _, sr := range series {
		vals := make([]*float64, len(ts))
		for i, t := range ts {
			if v, ok := sr.pts[t]; ok && !math.IsNaN(v) {
				v := v
				vals[i] = &v
			}
		}
		out.Series = append(out.Series, alignedSeries{Key: sr.key, Values: vals})
	}
	writeJSON(w, 200, out)
}
