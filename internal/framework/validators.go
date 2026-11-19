package framework

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// stringCheck adapts a plain func into a validator.String.
type stringCheck struct {
	description string
	check       func(string) error
}

func (v stringCheck) Description(context.Context) string         { return v.description }
func (v stringCheck) MarkdownDescription(context.Context) string { return v.description }

func (v stringCheck) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if err := v.check(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", err.Error())
	}
}

var (
	objectNameRe = regexp.MustCompile(`^[^#,;](?:[^,;]*)$`)
	macRe        = regexp.MustCompile(`^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$`)
)

// ObjectName validates the SFOS "sfos-object-name" format: no commas or
// semicolons, no leading '#', no leading or trailing whitespace.
func ObjectName() validator.String {
	return stringCheck{
		description: "must be a valid SFOS object name",
		check: func(s string) error {
			if strings.TrimSpace(s) != s {
				return fmt.Errorf("%q must not have leading or trailing whitespace", s)
			}
			if !objectNameRe.MatchString(s) {
				return fmt.Errorf("%q is not a valid SFOS object name: commas and semicolons are not allowed and it must not start with '#'", s)
			}
			return nil
		},
	}
}

// IPAddress validates a canonical IPv4 (bits == 32) or IPv6 (bits == 128) address.
func IPAddress(bits int) validator.String {
	return stringCheck{
		description: fmt.Sprintf("must be a canonical IPv%d address", family(bits)),
		check: func(s string) error {
			a, err := netip.ParseAddr(s)
			if err != nil || a.BitLen() != bits || a.Zone() != "" {
				return fmt.Errorf("%q is not a valid IPv%d address", s, family(bits))
			}
			if a.String() != s {
				return fmt.Errorf("%q must be written in canonical form %q", s, a.String())
			}
			return nil
		},
	}
}

// Prefix validates a canonical network in CIDR notation, e.g. "192.0.2.0/24",
// whose prefix length lies within [minLen, maxLen].
func Prefix(bits, minLen, maxLen int) validator.String {
	return stringCheck{
		description: fmt.Sprintf("must be an IPv%d network in CIDR notation", family(bits)),
		check: func(s string) error {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().BitLen() != bits {
				return fmt.Errorf("%q is not a valid IPv%d network in CIDR notation", s, family(bits))
			}
			if p.Bits() < minLen || p.Bits() > maxLen {
				return fmt.Errorf("prefix length of %q must be between %d and %d", s, minLen, maxLen)
			}
			if p.Masked().String() != s {
				return fmt.Errorf("%q must be the canonical network address %q", s, p.Masked().String())
			}
			return nil
		},
	}
}

// InterfaceAddress validates a host address with prefix length, e.g. "192.0.2.1/24".
func InterfaceAddress(bits int) validator.String {
	return stringCheck{
		description: fmt.Sprintf("must be an IPv%d address with prefix length", family(bits)),
		check: func(s string) error {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().BitLen() != bits || p.Bits() == 0 {
				return fmt.Errorf("%q is not an IPv%d address with prefix length, e.g. %s", s, family(bits), map[int]string{32: "192.0.2.1/24", 128: "2001:db8::1/64"}[bits])
			}
			if p.String() != s {
				return fmt.Errorf("%q must be written in canonical form %q", s, p.String())
			}
			return nil
		},
	}
}

// MACAddress validates a colon separated MAC address, e.g. "00:1a:2b:3c:4d:5e".
func MACAddress() validator.String {
	return stringCheck{
		description: "must be a MAC address such as 00:1a:2b:3c:4d:5e",
		check: func(s string) error {
			if !macRe.MatchString(s) {
				return fmt.Errorf("%q is not a colon separated MAC address such as 00:1a:2b:3c:4d:5e", s)
			}
			return nil
		},
	}
}

func family(bits int) int {
	if bits == 128 {
		return 6
	}
	return 4
}

// boolTrue rejects false, for flags that only make sense when switched on.
type boolTrue struct{}

// BoolTrue returns a validator that only accepts true.
func BoolTrue() validator.Bool { return boolTrue{} }

func (boolTrue) Description(context.Context) string         { return "must be true when set" }
func (boolTrue) MarkdownDescription(context.Context) string { return "must be `true` when set" }

func (boolTrue) ValidateBool(_ context.Context, req validator.BoolRequest, resp *validator.BoolResponse) {
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() && !req.ConfigValue.ValueBool() {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", "must be true when set; omit the attribute instead")
	}
}
