package store

import "context"

// Stats is a summary of stored data (used by `sentrix-server stats` and acceptance tests).
type Stats struct {
	Hosts          int            `json:"hosts"`
	SeriesByPrefix map[string]int `json:"series_by_prefix"`
	RawRows        int            `json:"raw_rows"`
	MinuteRows     int            `json:"minute_rows"`
	HourRows       int            `json:"hour_rows"`
}

// Stats computes a data summary.
func (d *DB) Stats(ctx context.Context) (Stats, error) {
	st := Stats{SeriesByPrefix: map[string]int{}}
	for q, dst := range map[string]*int{
		`SELECT COUNT(*) FROM hosts`:       &st.Hosts,
		`SELECT COUNT(*) FROM metrics_raw`: &st.RawRows,
		`SELECT COUNT(*) FROM metrics_1m`:  &st.MinuteRows,
		`SELECT COUNT(*) FROM metrics_1h`:  &st.HourRows,
	} {
		if err := d.sql.QueryRowContext(ctx, q).Scan(dst); err != nil {
			return st, err
		}
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT substr(name, 1, instr(name, '.') - 1) AS p, COUNT(*) FROM series GROUP BY p`)
	if err != nil {
		return st, err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			return st, err
		}
		st.SeriesByPrefix[p] = n
	}
	return st, rows.Err()
}
