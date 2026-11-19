package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/provider"
)

// Generate documentation with tfplugindocs (see docs/ and templates/).
//go:generate go tool tfplugindocs generate --provider-name sophosfirewall

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/jubinaghara/sophosfirewall",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
