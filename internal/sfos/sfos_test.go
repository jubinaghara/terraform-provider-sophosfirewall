package sfos

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type zoneList struct {
	Zones []NameRef `json:"zones"`
}

func TestSelectorJSON(t *testing.T) {
	b, _ := json.Marshal(MatchAny[zoneList]())
	if string(b) != `{"any":true}` {
		t.Fatalf("any = %s", b)
	}
	b, _ = json.Marshal(Match(zoneList{Zones: []NameRef{{Name: "LAN"}}}))
	if string(b) != `{"zones":[{"name":"LAN"}]}` {
		t.Fatalf("match = %s", b)
	}
	var s Selector[zoneList]
	if err := json.Unmarshal([]byte(`{"zones":[{"name":"WAN"}]}`), &s); err != nil || s.Any || s.Items.Zones[0].Name != "WAN" {
		t.Fatalf("unmarshal = %+v, %v", s, err)
	}
	if err := json.Unmarshal([]byte(`{"any":true}`), &s); err != nil || !s.Any || s.Items.Zones != nil {
		t.Fatalf("unmarshal any = %+v, %v", s, err)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"172.16.16.16:4444":                                 "https://172.16.16.16:4444/api/firewall-config/v1",
		"https://fw.example.com:4444/":                      "https://fw.example.com:4444/api/firewall-config/v1",
		"https://fw.example.com/api/firewall-config/v1?x=1": "https://fw.example.com/api/firewall-config/v1",
	} {
		got, err := NormalizeEndpoint(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEndpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeEndpoint(""); err == nil {
		t.Error("expected error for empty endpoint")
	}
}

func TestClientErrorsAndRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("missing bearer token")
		}
		switch r.URL.Path {
		case BasePath + "/flaky":
			if atomic.AddInt32(&calls, 1) == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"name":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"notFound","message":"Resource not found."}`))
		}
	}))
	defer srv.Close()

	c, err := NewClient(Config{Endpoint: srv.URL, APIKey: "k", MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	var out NameRef
	if err := c.Get(context.Background(), "/flaky", &out); err != nil || out.Name != "ok" || calls != 2 {
		t.Fatalf("retry: out=%+v err=%v calls=%d", out, err, calls)
	}
	err = c.Get(context.Background(), ItemPath("/network/zones", "a b"), &out)
	if !IsNotFound(err) {
		t.Fatalf("expected not found, got %v", err)
	}
	if got := err.Error(); got != "GET /network/zones/a%20b: HTTP 404 notFound: Resource not found." {
		t.Fatalf("error message = %q", got)
	}
}
