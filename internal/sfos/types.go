package sfos

import "encoding/json"

// NameRef references another SFOS object by name, e.g. {"name": "LAN"}.
type NameRef struct {
	Name string `json:"name"`
}

// Selector models the API's recurring "match any or match these" union:
//
//	{"any": true}                     // Any == true
//	{"zones": [{"name": "LAN"}]}      // Items
//
// T is the struct holding the concrete lists for the selected branch.
type Selector[T any] struct {
	Any   bool
	Items T
}

// MatchAny returns a selector matching everything.
func MatchAny[T any]() Selector[T] { return Selector[T]{Any: true} }

// Match returns a selector matching the given items.
func Match[T any](items T) Selector[T] { return Selector[T]{Items: items} }

// MarshalJSON implements json.Marshaler.
func (s Selector[T]) MarshalJSON() ([]byte, error) {
	if s.Any {
		return []byte(`{"any":true}`), nil
	}
	return json.Marshal(s.Items)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Selector[T]) UnmarshalJSON(b []byte) error {
	*s = Selector[T]{}
	if string(b) == "null" {
		return nil
	}
	var probe struct {
		Any bool `json:"any"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return err
	}
	if probe.Any {
		s.Any = true
		return nil
	}
	return json.Unmarshal(b, &s.Items)
}

// Ptr returns a pointer to v.
func Ptr[T any](v T) *T { return &v }
