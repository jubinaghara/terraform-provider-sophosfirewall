# Contributing

## Adding a new object type

Most SFOS objects follow the same REST contract, so adding one takes a single
file plus a line in the registry. As an example, here is how an IPv4 address
group (`/network/address-groups/ipv4`) would be added.

### 1. Look up the API

Find the collection in the OpenAPI specification and note:

* the create (`POST`) body and the read (`GET {idOrName}`) response,
* which fields are missing from the `PATCH` body (they are create-only and
  usually need `RequiresReplace`),
* server-side defaults and read-only fields.

### 2. Describe the object

Create `internal/services/addressgroups/ipv4_group.go`:

```go
type ipv4GroupModel struct {             // Terraform side, `tfsdk` tags
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Addresses   types.Set    `tfsdk:"addresses"`
}

type ipv4Group struct {                  // API side, `json` tags
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name"`
	Description *string        `json:"description,omitempty"`
	Addresses   []sfos.NameRef `json:"ipv4Addresses"`
}

var IPv4Group = &framework.Resource[ipv4GroupModel, ipv4Group]{
	Name:  "ipv4_group",                 // -> sophosfirewall_ipv4_group
	Title: "IPv4 address group",
	Path:  "/network/address-groups/ipv4",
	Schema: schema.Schema{
		MarkdownDescription: "Manages an IPv4 address group.",
		Attributes: map[string]schema.Attribute{
			"id":          framework.IDAttribute(),
			"name":        framework.NameAttribute("IPv4 address group", 60, false),
			"description": framework.DescriptionAttribute(255),
			"addresses":   framework.NameSetAttribute("Names of IPv4 address objects."),
		},
	},
	Expand: func(ctx context.Context, m *ipv4GroupModel, diags *diag.Diagnostics) *ipv4Group {
		return &ipv4Group{
			Name:        m.Name.ValueString(),
			Description: framework.StringPtr(m.Description),
			Addresses:   framework.Refs(ctx, m.Addresses, diags),
		}
	},
	Flatten: func(ctx context.Context, a *ipv4Group, _ *ipv4GroupModel, diags *diag.Diagnostics) *ipv4GroupModel {
		return &ipv4GroupModel{
			ID:          types.StringValue(a.ID),
			Name:        types.StringValue(a.Name),
			Description: framework.StringOr(a.Description, ""),
			Addresses:   framework.RefSet(ctx, a.Addresses, diags),
		}
	},
}
```

That is all: create, read, update (as a minimal JSON merge patch), delete,
import by name or UUID and a matching `sophosfirewall_ipv4_group` data source come from
`internal/framework`.

Optional spec fields cover the less common cases:

| Field | Use it for |
|-------|-----------|
| `CreateOnly` | JSON keys accepted on create but never sent in a `PATCH` |
| `Validate` | cross-attribute checks on the configuration |
| `AfterUpdate` | follow-up calls, e.g. moving a rule (`shared.MoveIfChanged`) |
| `Adopt` | objects that always exist and cannot be created or deleted (physical interfaces) |
| `NoDataSource` | skipping the derived data source |

### 3. Register it

Add `addressgroups.IPv4Group` to `internal/provider/registry.go`.

### 4. Test, document, example

* Add `ipv4_group_test.go` next to the spec using `acctest.New(t)`. If the
  collection is new, add it to `acctest.Collections()`, including any defaults
  the real firewall fills in.
* Add `examples/resources/sophosfirewall_ipv4_group/resource.tf` and `import.sh`.
* Run `make fmt docs check`.

## Guidelines

* **Expand** must leave unknown and null values unset (`framework.StringPtr`
  and friends do this), so that only configured values are sent.
* **Flatten** turns absent or empty API values into null. Keep optional blocks
  the user does not configure null (`framework.Managed(prior, ...)`) so
  firewall defaults do not show up as drift.
* Lists of names whose order does not matter are sets.
* Match criteria use `sfos.Selector[T]`: a nil block or null set means *any*.
* Name attributes after the web admin console where it helps users, and use
  the API's enum values verbatim.
