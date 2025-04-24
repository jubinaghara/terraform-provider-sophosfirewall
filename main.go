// main.go - Provider entry point

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/provider"
)

// Main function - entry point for the provider
func main() {
	// Define a flag for enabling debug mode
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers")
	flag.Parse()

	// Define provider options, including debug and address for the registry
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/jubinaghara/terraform-provider-sophosfirewall", // Update with your username/repo name
		Debug:   debug,
	}

	// Start serving the provider
	err := providerserver.Serve(context.Background(), provider.New, opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
