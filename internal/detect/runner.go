// Package detect runs compiled detection queries through database/sql.
package detect

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
)

type Query struct {
	ID   string `json:"id"`
	SQL  string `json:"sql"`
	Args []any  `json:"args"`
}

type Finding struct {
	Rule    string
	EventID string
	TimeMS  int64
}

func ReadQueries(r io.Reader) ([]Query, error) {
	var queries []Query
	decoder := json.NewDecoder(r)
	decoder.UseNumber()
	if err := decoder.Decode(&queries); err != nil {
		return nil, err
	}
	for i := range queries {
		for j, arg := range queries[i].Args {
			switch v := arg.(type) {
			case json.Number:
				n, err := v.Int64()
				if err != nil {
					return nil, err
				}
				queries[i].Args[j] = n
			case []any:
				list := make([]string, len(v))
				for k, item := range v {
					var ok bool
					if list[k], ok = item.(string); !ok {
						return nil, fmt.Errorf("non-string list argument to %s", queries[i].ID)
					}
				}
				queries[i].Args[j] = list
			}
		}
	}
	return queries, nil
}

// Run uses the caller's DuckDB database/sql connection and the trusted compiler's query bundle.
func Run(ctx context.Context, db *sql.DB, queries []Query) ([]Finding, error) {
	var findings []Finding
	for _, query := range queries {
		matches, err := runQuery(ctx, db, query)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", query.ID, err)
		}
		findings = append(findings, matches...)
	}
	return findings, nil
}

func runQuery(ctx context.Context, db *sql.DB, q Query) ([]Finding, error) {
	rows, err := db.QueryContext(ctx, q.SQL, q.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []Finding
	for rows.Next() {
		f := Finding{Rule: q.ID}
		if err = rows.Scan(&f.EventID, &f.TimeMS); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
