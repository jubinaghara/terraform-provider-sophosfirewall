package framework

import (
	"encoding/json"
	"testing"
)

func TestMergePatch(t *testing.T) {
	cases := []struct {
		name, old, new, want string
	}{
		{"unchanged", `{"a":1,"b":[1]}`, `{"a":1,"b":[1]}`, `{}`},
		{"changed scalar", `{"a":1}`, `{"a":2}`, `{"a":2}`},
		{"added and removed", `{"a":1}`, `{"b":2}`, `{"a":null,"b":2}`},
		{"arrays replaced whole", `{"a":[1,2]}`, `{"a":[2]}`, `{"a":[2]}`},
		{"nested diff", `{"o":{"x":1,"y":2}}`, `{"o":{"x":1,"y":3}}`, `{"o":{"y":3}}`},
		{"nested removal", `{"o":{"x":1,"y":2}}`, `{"o":{"x":1}}`, `{"o":{"y":null}}`},
		{"oneOf switch to any", `{"z":{"zones":[{"name":"LAN"}]}}`, `{"z":{"any":true}}`, `{"z":{"any":true}}`},
		{"oneOf switch from any", `{"z":{"any":true}}`, `{"z":{"zones":[]}}`, `{"z":{"zones":[]}}`},
		{"object removed", `{"o":{"x":1}}`, `{}`, `{"o":null}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var o, n map[string]any
			_ = json.Unmarshal([]byte(tc.old), &o)
			_ = json.Unmarshal([]byte(tc.new), &n)
			got, _ := json.Marshal(MergePatch(o, n))
			var g, w any
			_ = json.Unmarshal(got, &g)
			_ = json.Unmarshal([]byte(tc.want), &w)
			gb, _ := json.Marshal(g)
			wb, _ := json.Marshal(w)
			if string(gb) != string(wb) {
				t.Fatalf("MergePatch(%s, %s) = %s, want %s", tc.old, tc.new, gb, wb)
			}
		})
	}
}
