package writegate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ConditionalHTTP connects to a trusted mutation service implementing strong
// ETags and atomic If-Match. Register it only after verifying that contract.
// The service must reject expired credentials and honor Idempotency-Key.
type ConditionalHTTP struct {
	BaseURL    string
	Client     *http.Client
	ReadBearer string
	// Mint obtains an audience-, action-, target-, and expiry-bound credential.
	Mint func(context.Context, Token) (string, error)
}

func (c ConditionalHTTP) perform(ctx context.Context, method string, r Request, bearer string, body []byte, headers http.Header) (*http.Response, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("conditional service requires a trusted HTTPS base URL")
	}
	if !opaqueID.MatchString(r.Connector) || !opaqueID.MatchString(string(r.Action)) || !opaqueID.MatchString(r.Target) {
		return nil, errors.New("invalid conditional resource identity")
	}
	u = u.JoinPath(r.Connector, string(r.Action), r.Target)
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	if bearer == "" {
		return nil, errors.New("missing scoped service credential")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	client := http.Client{Timeout: 15 * time.Second}
	if c.Client != nil {
		client = *c.Client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client.Do(req)
}

func (c ConditionalHTTP) Read(ctx context.Context, r Request) (State, error) {
	res, err := c.perform(ctx, http.MethodGet, r, c.ReadBearer, nil, nil)
	if err != nil {
		return State{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return State{}, fmt.Errorf("conditional state HTTP %d", res.StatusCode)
	}
	revision := res.Header.Get("ETag")
	if !strongETag(revision) {
		return State{}, errors.New("missing strong conditional revision")
	}
	var state struct {
		Active  *bool             `json:"active"`
		Details map[string]string `json:"details"`
	}
	const limit = 1 << 20
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return State{}, err
	}
	if len(body) > limit {
		return State{}, errors.New("conditional state too large")
	}
	if err = json.Unmarshal(body, &state); err != nil {
		return State{}, err
	}
	if state.Active == nil {
		return State{}, errors.New("conditional state missing active flag")
	}
	return State{Revision: revision, Active: *state.Active, Details: state.Details}, nil
}

func strongETag(value string) bool {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, c := range []byte(value[1 : len(value)-1]) {
		if c < 0x21 || c == '"' || c == 0x7f {
			return false
		}
	}
	return true
}

func (c ConditionalHTTP) ApplyIfRevision(ctx context.Context, t Token) error {
	if !strongETag(t.Revision) || c.Mint == nil || t.Key == "" || !time.Now().Before(t.Expires) {
		return errors.New("missing or expired conditional execution scope")
	}
	ctx, cancel := context.WithDeadline(ctx, t.Expires)
	defer cancel()
	credential, err := c.Mint(ctx, t)
	if err != nil {
		return err
	}
	h := http.Header{}
	h.Set("If-Match", t.Revision)
	h.Set("Idempotency-Key", t.Key)
	h.Set("Content-Type", "application/json")
	res, err := c.perform(ctx, http.MethodPatch, t.Request, credential, []byte(`{"active":false}`), h)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("conditional mutation HTTP %d", res.StatusCode)
	}
	return nil
}
