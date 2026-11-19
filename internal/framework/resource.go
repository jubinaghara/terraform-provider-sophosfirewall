package framework

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/sfos"
)

var (
	_ resource.ResourceWithConfigure      = (*genericResource[struct{}, struct{}])(nil)
	_ resource.ResourceWithImportState    = (*genericResource[struct{}, struct{}])(nil)
	_ resource.ResourceWithValidateConfig = (*genericResource[struct{}, struct{}])(nil)
)

type genericResource[M any, A any] struct {
	spec   *Resource[M, A]
	client *sfos.Client
}

func (r *genericResource[M, A]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.spec.Name
}

func (r *genericResource[M, A]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = r.spec.Schema
}

func (r *genericResource[M, A]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFrom(req.ProviderData, &resp.Diagnostics)
}

func (r *genericResource[M, A]) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if r.spec.Validate == nil {
		return
	}
	var m M
	// The configuration may still contain unknown values that the model
	// cannot hold; validation is then deferred to the next phase.
	if d := req.Config.Get(ctx, &m); d.HasError() {
		return
	}
	r.spec.Validate(ctx, &m, &resp.Diagnostics)
}

func (r *genericResource[M, A]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := r.spec.Expand(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	name := stringAttr(ctx, req.Plan, "name", &resp.Diagnostics)

	var id string
	if r.spec.Adopt {
		var existing json.RawMessage
		if err := r.client.Get(ctx, sfos.ItemPath(r.spec.Path, name), &existing); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Unable to find %s %q", r.spec.Title, name),
				fmt.Sprintf("A %s cannot be created, only adopted, so it must already exist on the firewall: %s", r.spec.Title, err))
			return
		}
		id = idOf(existing)
		patch, err := toObject(body)
		if err != nil {
			resp.Diagnostics.AddError("Unable to encode request", err.Error())
			return
		}
		r.stripCreateOnly(patch)
		if err := r.client.Patch(ctx, sfos.ItemPath(r.spec.Path, id), patch, nil); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Unable to configure %s %q", r.spec.Title, name), err.Error())
			return
		}
	} else {
		var created json.RawMessage
		if err := r.client.Post(ctx, r.spec.Path, body, &created); err != nil {
			detail := err.Error()
			if sfos.IsRunConfigFailed(err) {
				// The firewall saved the object but could not activate it.
				// Roll it back so a retry does not fail with "already exists".
				detail += "\n\nThe firewall stored the object but could not activate it. " + r.rollback(ctx, name)
			}
			resp.Diagnostics.AddError(fmt.Sprintf("Unable to create %s %q", r.spec.Title, name), detail)
			return
		}
		id = idOf(created)
	}
	if id == "" {
		id = name
	}

	m, found := r.read(ctx, id, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to read %s %q after creation", r.spec.Title, name), "The firewall returned 404 Not Found.")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *genericResource[M, A]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := stringAttr(ctx, req.State, "id", &resp.Diagnostics)

	// Right after `terraform import` only the id is known: flatten the full
	// object instead of mirroring the (empty) prior state.
	prior := &state
	if v := attr[types.String](ctx, req.State, "name", &resp.Diagnostics); v.IsNull() {
		prior = nil
	}

	m, found := r.read(ctx, id, prior, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *genericResource[M, A]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := stringAttr(ctx, req.State, "id", &resp.Diagnostics)

	// Values that are unknown in the plan (computed by the firewall) are
	// masked in the prior state too, so they are neither sent nor nulled.
	masked, err := maskUnknown(req.Plan.Raw, req.State.Raw)
	if err != nil {
		resp.Diagnostics.AddError("Unable to compute update", err.Error())
		return
	}
	var before M
	resp.Diagnostics.Append(tfsdk.State{Schema: req.State.Schema, Raw: masked}.Get(ctx, &before)...)
	if resp.Diagnostics.HasError() {
		return
	}

	newBody := r.spec.Expand(ctx, &plan, &resp.Diagnostics)
	oldBody := r.spec.Expand(ctx, &before, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	newObj, err := toObject(newBody)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode request", err.Error())
		return
	}
	oldObj, err := toObject(oldBody)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode request", err.Error())
		return
	}
	patch := MergePatch(oldObj, newObj)
	r.stripCreateOnly(patch)

	if len(patch) > 0 {
		if err := r.client.Patch(ctx, sfos.ItemPath(r.spec.Path, id), patch, nil); err != nil {
			resp.Diagnostics.AddError(fmt.Sprintf("Unable to update %s %q", r.spec.Title, id), err.Error())
			return
		}
	}
	if r.spec.AfterUpdate != nil {
		r.spec.AfterUpdate(ctx, r.client, &plan, &state, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	m, found := r.read(ctx, id, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !found {
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to read %s %q after update", r.spec.Title, id), "The firewall returned 404 Not Found.")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, m)...)
}

func (r *genericResource[M, A]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.spec.Adopt {
		// Nothing to delete on the appliance; Terraform simply stops managing it.
		return
	}
	id := stringAttr(ctx, req.State, "id", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.deleteItem(ctx, id); err != nil {
		resp.Diagnostics.AddError(fmt.Sprintf("Unable to delete %s %q", r.spec.Title, id), err.Error())
	}
}

// deleteItem deletes an object and treats it as deleted once it is gone.
// The firewall sometimes reports "delRunConfigFailed" or "deleted": false
// while still removing the object, so the outcome is checked with a read.
func (r *genericResource[M, A]) deleteItem(ctx context.Context, id string) error {
	path := sfos.ItemPath(r.spec.Path, id)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		err = r.client.Delete(ctx, path)
		if sfos.IsNotFound(err) || (err == nil && attempt == 0) {
			return nil
		}
		var existing json.RawMessage
		if getErr := r.client.Get(ctx, path, &existing); sfos.IsNotFound(getErr) {
			return nil
		}
		if err == nil {
			err = fmt.Errorf("DELETE %s succeeded but the object still exists", path)
		}
	}
	return err
}

// rollback removes an object the firewall stored despite a failed create
// and returns a sentence describing the outcome for the error message.
func (r *genericResource[M, A]) rollback(ctx context.Context, name string) string {
	if name == "" {
		return "Check the firewall for a leftover object before retrying."
	}
	if err := r.deleteItem(ctx, name); err != nil {
		return fmt.Sprintf("Removing it again failed (%s); delete %q on the firewall before retrying.", err, name)
	}
	return "It has been removed again, so the create can be retried once the cause is fixed."
}

// ImportState accepts either the UUID or the name of the object.
func (r *genericResource[M, A]) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// read fetches the object and flattens it. found is false on 404.
func (r *genericResource[M, A]) read(ctx context.Context, idOrName string, prior *M, diags *diag.Diagnostics) (*M, bool) {
	var a A
	if err := r.client.Get(ctx, sfos.ItemPath(r.spec.Path, idOrName), &a); err != nil {
		if sfos.IsNotFound(err) {
			return nil, false
		}
		diags.AddError(fmt.Sprintf("Unable to read %s %q", r.spec.Title, idOrName), err.Error())
		return nil, false
	}
	return r.spec.Flatten(ctx, &a, prior, diags), true
}

func (r *genericResource[M, A]) stripCreateOnly(patch map[string]any) {
	for _, k := range r.spec.CreateOnly {
		delete(patch, k)
	}
}

// --- helpers shared by resources and data sources ---

type attrGetter interface {
	GetAttribute(ctx context.Context, p path.Path, target any) diag.Diagnostics
}

func attr[T any](ctx context.Context, src attrGetter, name string, diags *diag.Diagnostics) T {
	var v T
	diags.Append(src.GetAttribute(ctx, path.Root(name), &v)...)
	return v
}

func stringAttr(ctx context.Context, src attrGetter, name string, diags *diag.Diagnostics) string {
	return attr[types.String](ctx, src, name, diags).ValueString()
}

func clientFrom(providerData any, diags *diag.Diagnostics) *sfos.Client {
	if providerData == nil {
		return nil
	}
	c, ok := providerData.(*sfos.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("Expected *sfos.Client, got %T. Please report this issue to the provider developers.", providerData))
	}
	return c
}

func idOf(raw json.RawMessage) string {
	var v struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.ID
}

func toObject(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	obj := map[string]any{}
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, err
	}
	return obj, nil
}
