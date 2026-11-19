// Package framework turns a declarative description of an SFOS REST
// collection into a fully working Terraform resource and data source.
//
// Most SFOS objects follow the same contract:
//
//	POST   {Path}              create
//	GET    {Path}/{idOrName}   read
//	PATCH  {Path}/{idOrName}   update (JSON merge patch, RFC 7396)
//	DELETE {Path}/{idOrName}   delete
//
// so a new object type only has to supply its schema, a Terraform model M,
// an API payload type A and the two conversions between them. Everything
// else (CRUD, import, minimal PATCH bodies, drift handling, data source
// derivation) is implemented once here.
package framework

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

// Registration is what the provider needs to expose an object type.
type Registration interface {
	NewResource() resource.Resource
	// NewDataSource returns nil when the object has no data source.
	NewDataSource() datasource.DataSource
}

// Resource describes a Terraform resource backed by an SFOS REST collection.
//
// M is the Terraform model (a struct with `tfsdk` tags that must contain
// "id" and "name" attributes) and A is the JSON payload of the API object.
type Resource[M any, A any] struct {
	// Name is the type name without the provider prefix, e.g. "zone".
	Name string
	// Title is a human readable singular name, e.g. "zone".
	Title string
	// Path is the collection endpoint relative to the API base, e.g. "/network/zones".
	Path string
	// Schema is the resource schema. The data source schema is derived from it.
	Schema schema.Schema

	// Expand converts the Terraform model into the API payload. Unknown
	// values must be left unset so they are not sent.
	Expand func(ctx context.Context, m *M, diags *diag.Diagnostics) *A
	// Flatten converts an API object into the Terraform model. prior is the
	// planned or current state, or nil when importing or reading a data
	// source. Use it to keep optional blocks the user does not manage null
	// and to carry over write-only values.
	Flatten func(ctx context.Context, a *A, prior *M, diags *diag.Diagnostics) *M

	// CreateOnly lists top-level JSON keys accepted on create but never sent in a PATCH.
	CreateOnly []string
	// Adopt marks objects that always exist on the appliance and cannot be
	// created or deleted (e.g. physical interfaces). Create looks the object
	// up by name and patches it; Delete only removes it from state.
	Adopt bool
	// Validate performs cross-attribute checks on the configuration.
	Validate func(ctx context.Context, m *M, diags *diag.Diagnostics)
	// AfterUpdate runs after a successful PATCH, e.g. to move a rule.
	AfterUpdate func(ctx context.Context, c *sfos.Client, plan, state *M, diags *diag.Diagnostics)

	// NoDataSource disables the automatically derived data source.
	NoDataSource bool
}

// NewResource implements Registration.
func (s *Resource[M, A]) NewResource() resource.Resource {
	return &genericResource[M, A]{spec: s}
}

// NewDataSource implements Registration.
func (s *Resource[M, A]) NewDataSource() datasource.DataSource {
	if s.NoDataSource {
		return nil
	}
	return &genericDataSource[M, A]{spec: s}
}
