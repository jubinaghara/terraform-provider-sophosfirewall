BINARY  := terraform-provider-sophosfirewall
VERSION ?= 23.2.0
OS_ARCH := $(shell go env GOOS)_$(shell go env GOARCH)
PLUGIN_DIR := $(HOME)/.terraform.d/plugins/registry.terraform.io/jubinaghara/sophosfirewall/$(VERSION)/$(OS_ARCH)

.PHONY: build install test fmt vet docs check

build:
	go build -o $(BINARY) .

# Install into the local plugin directory for manual testing with Terraform.
install:
	mkdir -p $(PLUGIN_DIR)
	go build -ldflags "-X main.version=$(VERSION)" -o $(PLUGIN_DIR)/$(BINARY)_v$(VERSION) .

# Unit tests plus Terraform end-to-end tests against the in-memory API fake.
test:
	go test -cover ./...

fmt:
	gofmt -w .
	terraform fmt -recursive examples

vet:
	go vet ./...

# Regenerate docs/ from the schemas, examples/ and templates/.
docs:
	go generate ./...

check: vet test
	test -z "$$(gofmt -l .)"
	terraform fmt -check -recursive examples
