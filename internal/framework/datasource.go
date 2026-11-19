package framework

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

var _ datasource.DataSourceWithConfigure = (*genericDataSource[struct{}, struct{}])(nil)

// genericDataSource looks up an existing object by name. Its schema mirrors
// the resource schema with every attribute computed except "name".
type genericDataSource[M any, A any] struct {
	spec   *Resource[M, A]
	client *sfos.Client
}

func (d *genericDataSource[M, A]) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.spec.Name
}

func (d *genericDataSource[M, A]) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = dschema.Schema{
		MarkdownDescription: fmt.Sprintf("Looks up an existing %s by name.", d.spec.Title),
		Attributes:          dataSourceAttributes(d.spec.Schema.Attributes, true),
	}
}

func (d *genericDataSource[M, A]) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (d *genericDataSource[M, A]) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	name := stringAttr(ctx, req.Config, "name", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	var a A
	if err := d.client.Get(ctx, sfos.ItemPath(d.spec.Path, name), &a); err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to read %s %q", d.spec.Title, name), err.Error())
		return
	}
	m := d.spec.Flatten(ctx, &a, nil, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

// dataSourceAttributes converts resource attributes into computed data
// source attributes. At the top level "name" becomes the required lookup key.
func dataSourceAttributes(in map[string]rschema.Attribute, topLevel bool) map[string]dschema.Attribute {
	out := make(map[string]dschema.Attribute, len(in))
	for name, a := range in {
		required := topLevel && name == "name"
		out[name] = dataSourceAttribute(a, required)
	}
	return out
}

func dataSourceAttribute(a rschema.Attribute, required bool) dschema.Attribute {
	computed := !required
	switch v := a.(type) {
	case rschema.StringAttribute:
		return dschema.StringAttribute{Required: required, Computed: computed, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.Int64Attribute:
		return dschema.Int64Attribute{Computed: true, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.BoolAttribute:
		return dschema.BoolAttribute{Computed: true, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.ListAttribute:
		return dschema.ListAttribute{Computed: true, ElementType: v.ElementType, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.SetAttribute:
		return dschema.SetAttribute{Computed: true, ElementType: v.ElementType, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.MapAttribute:
		return dschema.MapAttribute{Computed: true, ElementType: v.ElementType, Sensitive: v.Sensitive, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.SingleNestedAttribute:
		return dschema.SingleNestedAttribute{Computed: true, Attributes: dataSourceAttributes(v.Attributes, false), MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.ListNestedAttribute:
		return dschema.ListNestedAttribute{Computed: true, NestedObject: dschema.NestedAttributeObject{Attributes: dataSourceAttributes(v.NestedObject.Attributes, false)}, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	case rschema.SetNestedAttribute:
		return dschema.SetNestedAttribute{Computed: true, NestedObject: dschema.NestedAttributeObject{Attributes: dataSourceAttributes(v.NestedObject.Attributes, false)}, MarkdownDescription: v.MarkdownDescription, Description: v.Description}
	default:
		panic(fmt.Sprintf("framework: attribute type %T is not supported by derived data sources", a))
	}
}
