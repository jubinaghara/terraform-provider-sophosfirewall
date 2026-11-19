// Package sfostest provides an in-memory fake of the SFOS configuration API
// for tests. It implements the generic collection contract (POST, GET, PATCH
// with JSON merge patch, DELETE, /move) and mimics a few behaviours of the
// real firewall that matter to the provider:
//
//   - empty arrays and nulls are omitted from responses,
//   - collections can define server-side defaults for omitted fields,
//   - switching a oneOf branch (e.g. {"any":true} -> {"zones":[...]})
//     replaces the object instead of merging it,
//   - write-only fields (rule positions) are never returned.
package sfostest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// Collection configures the behaviour of one API collection.
type Collection struct {
	// Defaults are merged into newly created objects for missing keys.
	Defaults map[string]any
	// WriteOnly keys are accepted but never stored or returned.
	WriteOnly []string
	// Movable collections accept POST {path}/move.
	Movable bool
	// OnCreate can derive server-side fields of a new object.
	OnCreate func(obj map[string]any)
}

// Server is a fake SFOS API.
type Server struct {
	*httptest.Server
	t           testing.TB
	mu          sync.Mutex
	collections map[string]Collection
	objects     map[string][]map[string]any // collection path -> objects in order
	seq         int
	// Moves records every /move request body, for assertions.
	Moves []map[string]any
}

// APIKey is the bearer token the fake server accepts.
const APIKey = "test-api-key"

// NewServer starts a fake server with the given collections.
func NewServer(t testing.TB, collections map[string]Collection) *Server {
	s := &Server{t: t, collections: collections, objects: map[string][]map[string]any{}}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// Seed stores an object as if it already existed on the appliance and returns its id.
func (s *Server) Seed(collection string, obj map[string]any) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj = deepCopy(obj)
	if _, ok := obj["id"]; !ok {
		obj["id"] = s.newID()
	}
	s.objects[collection] = append(s.objects[collection], obj)
	return obj["id"].(string)
}

// Get returns a copy of a stored object (nil if absent).
func (s *Server) Get(collection, idOrName string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, o := s.find(collection, idOrName); o != nil {
		return deepCopy(o)
	}
	return nil
}

// Names lists the names in a collection in order.
func (s *Server) Names(collection string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, o := range s.objects[collection] {
		out = append(out, fmt.Sprint(o["name"]))
	}
	return out
}

func (s *Server) newID() string {
	s.seq++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", s.seq)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+APIKey {
		writeError(w, http.StatusUnauthorized, "notAuthorized", "Authentication required.")
		return
	}
	const prefix = "/api/firewall-config/v1"
	p := strings.TrimPrefix(r.URL.EscapedPath(), prefix)

	var body map[string]any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		if len(b) > 0 {
			if err := json.Unmarshal(b, &body); err != nil {
				writeError(w, http.StatusBadRequest, "badRequest", err.Error())
				return
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Collection-level requests.
	if cfg, ok := s.collections[p]; ok {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "methodNotAllowed", r.Method)
			return
		}
		name, _ := body["name"].(string)
		if _, existing := s.find(p, name); existing != nil {
			writeError(w, http.StatusConflict, "resourceConflict", "Conflicts with an existing parameter.")
			return
		}
		obj := deepCopy(body)
		for _, k := range cfg.WriteOnly {
			delete(obj, k)
		}
		for k, v := range cfg.Defaults {
			if _, ok := obj[k]; !ok {
				obj[k] = deepCopy(map[string]any{"v": v})["v"]
			}
		}
		if cfg.OnCreate != nil {
			cfg.OnCreate(obj)
		}
		obj["id"] = s.newID()
		s.objects[p] = append(s.objects[p], obj)
		writeJSON(w, http.StatusCreated, present(obj))
		return
	}

	// Item-level requests: {collection}/{idOrName} or {collection}/move.
	i := strings.LastIndex(p, "/")
	if i < 0 {
		writeError(w, http.StatusNotFound, "notFound", "Not found.")
		return
	}
	collection, last := p[:i], p[i+1:]
	cfg, ok := s.collections[collection]
	if !ok {
		writeError(w, http.StatusNotFound, "notFound", "Not found.")
		return
	}
	if last == "move" && cfg.Movable && r.Method == http.MethodPost {
		s.Moves = append(s.Moves, body)
		writeJSON(w, http.StatusOK, map[string]any{"moved": true})
		return
	}
	idOrName, _ := url.PathUnescape(last)
	idx, obj := s.find(collection, idOrName)
	if obj == nil {
		writeError(w, http.StatusNotFound, "notFound", "Resource not found.")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, present(obj))
	case http.MethodPatch:
		for _, k := range cfg.WriteOnly {
			delete(body, k)
		}
		merged := applyPatch(obj, body)
		merged["id"] = obj["id"]
		s.objects[collection][idx] = merged
		writeJSON(w, http.StatusOK, present(merged))
	case http.MethodDelete:
		s.objects[collection] = append(s.objects[collection][:idx], s.objects[collection][idx+1:]...)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "methodNotAllowed", r.Method)
	}
}

func (s *Server) find(collection, idOrName string) (int, map[string]any) {
	for i, o := range s.objects[collection] {
		if o["id"] == idOrName || o["name"] == idOrName {
			return i, o
		}
	}
	return -1, nil
}

// applyPatch implements RFC 7396 plus the API's oneOf branch switching.
func applyPatch(target, patch map[string]any) map[string]any {
	out := deepCopy(target)
	for k, pv := range patch {
		if pv == nil {
			delete(out, k)
			continue
		}
		pm, pIsObj := pv.(map[string]any)
		tm, tIsObj := out[k].(map[string]any)
		if pIsObj && tIsObj && overlaps(tm, pm) {
			out[k] = applyPatch(tm, pm)
		} else {
			out[k] = deepCopy(map[string]any{"v": pv})["v"]
		}
	}
	return out
}

func overlaps(a, b map[string]any) bool {
	for k := range b {
		if _, ok := a[k]; ok {
			return true
		}
	}
	return false
}

// present removes nulls and empty arrays, like the real API responses.
func present(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			if val == nil {
				continue
			}
			if arr, ok := val.([]any); ok && len(arr) == 0 {
				continue
			}
			out[k] = present(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = present(val)
		}
		return out
	}
	return v
}

func deepCopy(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": code, "message": msg})
}
