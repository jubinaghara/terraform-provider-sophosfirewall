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
	"strconv"
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
	// AfterWrite can mimic firewall quirks: it runs on the stored object
	// after every create and PATCH, with the request body.
	AfterWrite func(obj, body map[string]any)
}

// SetAfterWrite installs Collection.AfterWrite on an existing collection.
func (s *Server) SetAfterWrite(collection string, fn func(obj, body map[string]any)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.collections[collection]
	cfg.AfterWrite = fn
	s.collections[collection] = cfg
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
		if r.Method == http.MethodGet {
			s.list(w, r, p)
			return
		}
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
		if cfg.AfterWrite != nil {
			cfg.AfterWrite(obj, body)
		}
		obj["id"] = s.newID()
		s.objects[p] = append(s.objects[p], obj)
		if cfg.Movable {
			s.placeNew(p, body)
		}
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
		s.move(w, collection, body)
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
		if cfg.AfterWrite != nil {
			cfg.AfterWrite(merged, body)
		}
		s.objects[collection][idx] = merged
		writeJSON(w, http.StatusOK, present(merged))
	case http.MethodDelete:
		s.objects[collection] = append(s.objects[collection][:idx], s.objects[collection][idx+1:]...)
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, "methodNotAllowed", r.Method)
	}
}

// listPageSize is the page size of collection listings (the API default).
const listPageSize = 50

// list serves GET {collection}?page=N like the real API.
func (s *Server) list(w http.ResponseWriter, r *http.Request, collection string) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	all := s.objects[collection]
	items := []any{}
	for i := (page - 1) * listPageSize; i < len(all) && i < page*listPageSize; i++ {
		items = append(items, present(all[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"pages": map[string]any{"current": page, "size": listPageSize, "maxSize": 100},
	})
}

// placeNew moves the just-appended object to the position requested on
// create, where all four positions are accepted.
func (s *Server) placeNew(collection string, body map[string]any) {
	objs := s.objects[collection]
	obj := objs[len(objs)-1]
	rest := objs[:len(objs)-1]
	at := len(rest)
	switch body["position"] {
	case "top":
		at = 0
	case "before", "after":
		ref, _ := body["referenceItem"].(map[string]any)
		for i, o := range rest {
			if o["name"] == ref["name"] {
				at = i
				if body["position"] == "after" {
					at++
				}
			}
		}
	}
	s.objects[collection] = append(append(append([]map[string]any{}, rest[:at]...), obj), rest[at:]...)
}

// move implements POST {collection}/move. Like SFOS v23 (and unlike its
// API specification) only "before" and "after" are accepted.
func (s *Server) move(w http.ResponseWriter, collection string, body map[string]any) {
	pos, _ := body["position"].(string)
	if pos != "before" && pos != "after" {
		writeError(w, http.StatusBadRequest, "invalidRequest",
			fmt.Sprintf("%s is not a valid MovePosition, allowed values are [after before]", pos))
		return
	}
	name, _ := body["name"].(string)
	ref, _ := body["referenceItem"].(map[string]any)
	refName, _ := ref["name"].(string)
	idx, obj := s.find(collection, name)
	if obj == nil || refName == "" || refName == name {
		writeError(w, http.StatusBadRequest, "invalidRequest", "Invalid rule or reference item.")
		return
	}
	rest := append(append([]map[string]any{}, s.objects[collection][:idx]...), s.objects[collection][idx+1:]...)
	at := -1
	for i, o := range rest {
		if o["name"] == refName {
			at = i
		}
	}
	if at < 0 {
		writeError(w, http.StatusNotFound, "notFound", "Reference item not found.")
		return
	}
	if pos == "after" {
		at++
	}
	out := append(append(append([]map[string]any{}, rest[:at]...), obj), rest[at:]...)
	s.objects[collection] = out
	writeJSON(w, http.StatusOK, map[string]any{"moved": true})
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
