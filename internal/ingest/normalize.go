package ingest

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func normalize(v Vendor, raw json.RawMessage) ([]Event, error) {
	switch v {
	case EntraSignIn, EntraAudit:
		return entra(v, raw)
	case Workspace, Calendar:
		return google(v, raw)
	case Notion:
		return notion(raw)
	default:
		return nil, errors.New("unknown vendor")
	}
}

func entra(v Vendor, raw json.RawMessage) ([]Event, error) {
	var x struct {
		ID, UserID, UserPrincipalName, IPAddress, CreatedDateTime, ActivityDateTime, ActivityDisplayName, Result, UniqueTokenIdentifier string
		AutonomousSystemNumber                                                                                                          json.Number
		Status                                                                                                                          *struct{ ErrorCode *int }
		Location                                                                                                                        struct {
			CountryOrRegion string
			GeoCoordinates  struct{ Latitude, Longitude *float64 }
		}
		DeviceDetail struct{ DeviceID string }
		InitiatedBy  struct {
			User struct{ ID, UserPrincipalName, IPAddress string }
			App  struct{ AppID string }
		}
		AuthenticationDetails []struct {
			AuthenticationMethod, AuthenticationStepResultDetail string
			Succeeded                                            bool
		}
		TargetResources []struct {
			ModifiedProperties []struct{ DisplayName, NewValue string }
		}
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return nil, err
	}
	src := Endpoint{IP: x.IPAddress, ASN: x.AutonomousSystemNumber.String(), Device: x.DeviceDetail.DeviceID, Country: x.Location.CountryOrRegion, Latitude: x.Location.GeoCoordinates.Latitude, Longitude: x.Location.GeoCoordinates.Longitude}
	var events []Event
	add := func(id, actor, ts string, class int, d Details) error {
		event, err := newEvent(v, raw, id, actor, ts, class, src, d)
		if err == nil {
			events = append(events, event)
		}
		return err
	}
	if v == EntraSignIn {
		user := x.UserID
		if user == "" {
			user = x.UserPrincipalName
		}
		d := Details{Kind: "login", Token: x.UniqueTokenIdentifier}
		if x.Status != nil && x.Status.ErrorCode != nil {
			switch *x.Status.ErrorCode {
			case 0:
				d.Outcome = "success"
			case 50126, 50034:
				d.Outcome = "failure"
			}
		}
		if err := add(x.ID, user, x.CreatedDateTime, 3002, d); err != nil {
			return nil, err
		}
		for i, step := range x.AuthenticationDetails {
			method := strings.ToLower(step.AuthenticationMethod)
			if !strings.Contains(method, "notification") && !strings.Contains(method, "push") {
				continue
			}
			outcome := "accept"
			if !step.Succeeded {
				result := strings.ToLower(step.AuthenticationStepResultDetail)
				if !strings.Contains(result, "denied") && !strings.Contains(result, "declined") {
					continue
				}
				outcome = "deny"
			}
			if err := add(x.ID+"/mfa/"+strconv.Itoa(i), user, x.CreatedDateTime, 3002, Details{Kind: "mfa_push", Outcome: outcome}); err != nil {
				return nil, err
			}
		}
		return events, nil
	}
	user := x.InitiatedBy.User.ID
	if user == "" {
		user = x.InitiatedBy.User.UserPrincipalName
	}
	if user == "" {
		user = x.InitiatedBy.App.AppID
	}
	src.IP = x.InitiatedBy.User.IPAddress
	d := Details{Kind: "account_change", Outcome: strings.ToLower(x.Result)}
	class := 3001
	name := strings.ToLower(x.ActivityDisplayName)
	if strings.Contains(name, "consent") || strings.Contains(name, "delegated permission") || strings.Contains(name, "app role assignment") {
		d.Kind = "oauth_grant"
		class = 6003
		var scopes []string
		for _, target := range x.TargetResources {
			for _, p := range target.ModifiedProperties {
				scopes = append(scopes, p.NewValue)
			}
		}
		d.Scope = strings.Join(scopes, " ")
	}
	if err := add(x.ID, user, x.ActivityDateTime, class, d); err != nil {
		return nil, err
	}
	return events, nil
}

func google(v Vendor, raw json.RawMessage) ([]Event, error) {
	var x struct {
		ID        struct{ Time, UniqueQualifier, CustomerID, ApplicationName string }
		Actor     struct{ Email, ProfileID string }
		IPAddress string
		Events    []struct {
			Name, Type string
			Parameters []struct {
				Name, Value string
				MultiValue  []string
			}
		}
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return nil, err
	}
	if x.ID.UniqueQualifier == "" || len(x.Events) == 0 {
		return nil, errors.New("missing Google event identity")
	}
	var events []Event
	user := x.Actor.ProfileID
	if user == "" {
		user = x.Actor.Email
	}
	for i, e := range x.Events {
		class := 6003
		d := Details{Kind: e.Name}
		src := Endpoint{IP: x.IPAddress}
		for _, p := range e.Parameters {
			switch p.Name {
			case "scope", "scopes":
				d.Scope = strings.Join(append([]string{p.Value}, p.MultiValue...), " ")
			case "token_id":
				d.Token = p.Value
			case "asn":
				src.ASN = p.Value
			case "device_id":
				src.Device = p.Value
			}
		}
		switch e.Name {
		case "login_success", "login_failure":
			class, d.Kind, d.Outcome = 3002, "login", "success"
			if e.Name == "login_failure" {
				d.Outcome = "failure"
			}
		case "authorize", "grant", "oauth_grant":
			d.Kind, d.Outcome = "oauth_grant", "success"
		case "change_calendar_acls", "calendar_share":
			d.Kind, d.Outcome = "share", "success"
		case "CREATE_USER", "DELETE_USER", "SUSPEND_USER", "UNSUSPEND_USER":
			class, d.Kind = 3001, "account_change"
		}
		id := strings.Join([]string{x.ID.CustomerID, x.ID.ApplicationName, x.ID.UniqueQualifier, strconv.Itoa(i)}, "/")
		event, err := newEvent(v, raw, id, user, x.ID.Time, class, src, d)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func notion(raw json.RawMessage) ([]Event, error) {
	var x struct {
		ID, Timestamp, Action string
		Actor                 struct{ ID string }
		IP                    string `json:"ip_address"`
		Details               struct{ Scopes []string }
	}
	if err := json.Unmarshal(raw, &x); err != nil {
		return nil, err
	}
	d := Details{Kind: x.Action, Scope: strings.Join(x.Details.Scopes, " ")}
	switch x.Action {
	case "oauth_grant", "integration.connected":
		d.Kind, d.Outcome = "oauth_grant", "success"
	case "page.shared", "share.created":
		d.Kind, d.Outcome = "share", "success"
	case "page.exported", "workspace.exported":
		d.Kind, d.Scope, d.Outcome = "export", "bulk_export", "success"
	}
	event, err := newEvent(Notion, raw, x.ID, x.Actor.ID, x.Timestamp, 6003, Endpoint{IP: x.IP}, d)
	if err != nil {
		return nil, err
	}
	return []Event{event}, nil
}
