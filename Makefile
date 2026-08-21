# SCBoX build & release. SCBoX is free: no license, no keys, no telemetry.
#
# Build the binary:                 make build
# Build + install to ~/.local/bin:  make install
# Cross-platform release artifacts:  make release   (needs goreleaser)
#
# All third-party deps are vendored under internal/third_party/, so builds need
# no network (GOPROXY=off works). Set VERSION to stamp `scbox version`.

BIN        ?= scbox
PREFIX     ?= $(HOME)/.local
INSTALL_DIR ?= $(PREFIX)/bin

VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install test vet release clean

# First-party packages only — the inlined third-party libraries under
# internal/third_party/ are frozen, trusted in-repo copies (see SUPPLY-CHAIN.md);
# we compile them but do not run our own test/vet gates over upstream code.
PKGS := $(shell go list ./... | grep -v '/internal/third_party/')

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

install: build
	mkdir -p $(INSTALL_DIR)
	install -m 0755 $(BIN) $(INSTALL_DIR)/$(BIN)
	@echo "installed $(INSTALL_DIR)/$(BIN)"

test:
	go test $(PKGS)

vet:
	go vet $(PKGS)

release:
	goreleaser release --clean

clean:
	rm -f $(BIN)
