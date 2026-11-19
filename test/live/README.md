# Live end-to-end test

`main.tf` creates one of every resource type on a **real** firewall, updates them in
place, reads each back through its data source, and destroys everything again. Use a lab
or non-production firewall running SFOS v23.0 or later.

Safety: all objects are named `TF-Live*` / `TFLive*`, addresses are in `10.98.0.0/16`,
and only the spare ports `Port3`–`Port6` and `PortF1` are used. Change these in
`main.tf` if they are in use on your firewall.

```sh
export SFOS_ENDPOINT=https://<firewall>:4444 SFOS_API_KEY=<key> SFOS_INSECURE=true

terraform init
terraform apply                             # pass 1: create
terraform output data_source_checks         # every value must be true
terraform plan -detailed-exitcode           # must report "No changes" (exit 0)
terraform apply -var v2=true                # pass 2: in-place updates
terraform plan -var v2=true -detailed-exitcode
terraform destroy -var v2=true
```

To test an unreleased build, point a `dev_overrides` block in a CLI configuration file
(`TF_CLI_CONFIG_FILE`) at the directory containing the built provider.

After `destroy`, Port3 stays in the DMZ zone with `10.98.3.1/24`, because a physical
port can only be adopted, not deleted. Unassign it again in the web console, or with:

```sh
curl -k -X PATCH "$SFOS_ENDPOINT/api/firewall-config/v1/network/interfaces/network-interfaces/Port3" \
  -H "Authorization: Bearer $SFOS_API_KEY" -H 'Content-Type: application/merge-patch+json' \
  -d '{"zone":null,"ipv4":{"assignmentType":"static","ipv4Address":"","cidr":0},"mtu":1500,"mss":1460}'
```

Only a blackhole static route is used: on the lab firewall the test was written against,
routes with a gateway or interface were rejected by the firewall itself
(`addRunConfigFailed`), and after a few such failures it rejected every route change. Add
`-var static_routes=false` to every command to leave the route out.
