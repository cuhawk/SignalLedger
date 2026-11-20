// Package ingest reads vendor audit pages and persists normalized OCSF events.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/cuhawk/SignalLedger/internal/merkle"
)

type Actor struct {
	User User `json:"user"`
}
type User struct {
	UID string `json:"uid"`
}
type Product struct {
	Name   string `json:"name"`
	Vendor string `json:"vendor_name"`
}
type Metadata struct {
	Version string  `json:"version"`
	UID     string  `json:"uid"`
	Product Product `json:"product"`
}
type Endpoint struct {
	IP        string   `json:"ip,omitempty"`
	ASN       string   `json:"asn,omitempty"`
	Device    string   `json:"device,omitempty"`
	Country   string   `json:"country,omitempty"`
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}
type Event struct {
	Time        int64    `json:"time"`
	Class       int      `json:"class_uid"`
	Category    int      `json:"category_uid"`
	Activity    int      `json:"activity_id"`
	Type        int      `json:"type_uid"`
	Severity    int      `json:"severity_id"`
	Status      int      `json:"status_id"`
	Actor       Actor    `json:"actor"`
	Metadata    Metadata `json:"metadata"`
	Source      Endpoint `json:"src_endpoint"`
	Details     Details  `json:"unmapped"`
	PayloadHash string   `json:"payload_sha256"`
}
type Details struct {
	Kind    string `json:"kind"`
	Outcome string `json:"outcome,omitempty"`
	Scope   string `json:"scope,omitempty"`
	Token   string `json:"token,omitempty"`
}
type Page struct {
	Events   []Event
	Rejected int
	Next     string
}
type Connector interface {
	Fetch(context.Context, time.Time, string) (Page, error)
}

type HTTP struct {
	Client     *http.Client
	Token      string
	RetryLimit int
	Sleep      func(context.Context, time.Duration) error
}

func retryDelay(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds >= 0 && seconds <= int64((1<<63-1)/time.Second) {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil && date.After(now) {
		return date.Sub(now)
	}
	return 0
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (h HTTP) get(ctx context.Context, u *url.URL, out any) error {
	client := http.Client{Timeout: 30 * time.Second}
	if h.Client != nil {
		client = *h.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sleep := h.Sleep
	if sleep == nil {
		sleep = wait
	}
	limit := h.RetryLimit
	if limit == 0 {
		limit = 5
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		if h.Token != "" {
			req.Header.Set("Authorization", "Bearer "+h.Token)
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode == 429 && attempt < limit {
			res.Body.Close()
			backoff := 250 * time.Millisecond << min(attempt, 7)
			delay := max(retryDelay(res.Header.Get("Retry-After"), time.Now()), backoff)
			delay += min(time.Duration(rand.Int64N(int64(backoff))), time.Duration(1<<63-1)-delay)
			if err = sleep(ctx, delay); err != nil {
				return err
			}
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			return fmt.Errorf("audit endpoint HTTP %d", res.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(res.Body, 32<<20|1))
		res.Body.Close()
		if err != nil {
			return err
		}
		if len(data) > 32<<20 {
			return errors.New("audit page too large")
		}
		return json.Unmarshal(data, out)
	}
}

type Vendor string

const (
	EntraSignIn Vendor = "entra-signin"
	EntraAudit  Vendor = "entra-audit"
	Workspace   Vendor = "workspace"
	Calendar    Vendor = "calendar"
	Notion      Vendor = "notion"
)

type Feed struct {
	HTTP   HTTP
	Vendor Vendor
	URL    string // Trusted audit API endpoint for the selected feed.
}

func (f Feed) Fetch(ctx context.Context, since time.Time, cursor string) (Page, error) {
	u, err := url.Parse(f.URL)
	if err != nil {
		return Page{}, err
	}
	if u.Host == "" || u.User != nil || (u.Scheme != "https" && (u.Scheme != "http" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "::1"))) {
		return Page{}, errors.New("invalid audit endpoint")
	}
	q := u.Query()
	var response struct {
		Value      []json.RawMessage `json:"value"`
		NextLink   string            `json:"@odata.nextLink"`
		Items      []json.RawMessage `json:"items"`
		NextPage   string            `json:"nextPageToken"`
		Results    []json.RawMessage `json:"results"`
		NextCursor string            `json:"next_cursor"`
		HasMore    bool              `json:"has_more"`
	}
	switch f.Vendor {
	case EntraSignIn, EntraAudit:
		field := "createdDateTime"
		if f.Vendor == EntraAudit {
			field = "activityDateTime"
		}
		if !since.IsZero() {
			q.Set("$filter", field+" ge "+since.Format(time.RFC3339Nano))
		}
		u.RawQuery = q.Encode()
		if cursor != "" {
			next, e := url.Parse(cursor)
			if e != nil {
				return Page{}, e
			}
			next = u.ResolveReference(next)
			if next.Host != u.Host || next.Scheme != u.Scheme || next.EscapedPath() != u.EscapedPath() || next.User != nil {
				return Page{}, errors.New("untrusted pagination URL")
			}
			u = next
		}
	case Workspace, Calendar:
		if !since.IsZero() {
			q.Set("startTime", since.Format(time.RFC3339Nano))
		}
		if cursor != "" {
			q.Set("pageToken", cursor)
		}
		u.RawQuery = q.Encode()
	case Notion:
		if !since.IsZero() {
			q.Set("start_time", since.Format(time.RFC3339Nano))
		}
		if cursor != "" {
			q.Set("start_cursor", cursor)
		}
		u.RawQuery = q.Encode()
	default:
		return Page{}, errors.New("unknown audit feed")
	}
	if err = f.HTTP.get(ctx, u, &response); err != nil {
		return Page{}, err
	}
	raw, next := response.Value, response.NextLink
	switch f.Vendor {
	case Workspace, Calendar:
		raw, next = response.Items, response.NextPage
	case Notion:
		raw, next = response.Results, response.NextCursor
		if response.HasMore && next == "" {
			return Page{}, errors.New("missing Notion cursor")
		}
	}
	if next != "" && next == cursor {
		return Page{}, errors.New("pagination loop")
	}
	page := Page{Next: next}
	for _, item := range raw {
		events, err := normalize(f.Vendor, item)
		if err != nil {
			page.Rejected++
			continue
		}
		page.Events = append(page.Events, events...)
	}
	return page, nil
}

func newEvent(v Vendor, raw json.RawMessage, id, actor, when string, class int, source Endpoint, details Details) (Event, error) {
	t, err := time.Parse(time.RFC3339Nano, when)
	if err != nil || id == "" {
		return Event{}, errors.New("missing event ID or timestamp")
	}
	data, err := merkle.Canonical(raw)
	if err != nil {
		return Event{}, err
	}
	hash := sha256.Sum256(data)
	if details.Token != "" {
		tokenHash := sha256.Sum256([]byte(details.Token))
		details.Token = hex.EncodeToString(tokenHash[:])
	}
	category := 3
	if class == 6003 {
		category = 6
	}
	activity := 0
	if class == 3002 {
		activity = 1
	}
	status := 0
	switch details.Outcome {
	case "success", "accept":
		status = 1
	case "failure", "deny":
		status = 2
	}
	vendor := "Google"
	if v == EntraSignIn || v == EntraAudit {
		vendor = "Microsoft"
	}
	if v == Notion {
		vendor = "Notion"
	}
	return Event{Time: t.UnixMilli(), Class: class, Category: category, Activity: activity, Type: class*100 + activity, Severity: 1, Status: status,
		Actor: Actor{User: User{UID: actor}}, Metadata: Metadata{Version: "1.4.0", UID: id, Product: Product{Name: string(v), Vendor: vendor}}, Source: source, Details: details, PayloadHash: hex.EncodeToString(hash[:])}, nil
}
