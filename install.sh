#!/bin/sh
# SCBoX installer - builds from source and installs the binary. SCBoX is free
# and has no license, no telemetry, and no network calls at build or run time
# (all dependencies are vendored in-tree under internal/third_party/).
#
# Run it from a checkout of the repo:
#
#   ./install.sh
#
# Config via env:
#   INSTALL_DIR   install location   (default: ~/.local/bin)
#   BIN           binary name        (default: scbox)
set -eu

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
BIN="${BIN:-scbox}"

say() { printf '\033[36mscbox-install:\033[0m %s\n' "$*"; }
die() { printf '\033[31mscbox-install: %s\033[0m\n' "$*" >&2; exit 1; }

# Must run from the repo root (where main.go / go.mod live).
[ -f go.mod ] && [ -f main.go ] || die "run this from the SCBoX source directory (go.mod not found)"
command -v go >/dev/null 2>&1 || die "Go toolchain not found - install Go 1.26+ and re-run"

say "building $BIN from source (offline, vendored deps)…"
GOPROXY=off CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" .

mkdir -p "$INSTALL_DIR"
install -m 0755 "$BIN" "$INSTALL_DIR/$BIN"
say "installed to $INSTALL_DIR/$BIN"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "add $INSTALL_DIR to your PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

say "done. Try:  $BIN <package-dir | name@version>"
say "To gate npm installs:  source scripts/npm-guard.sh   # add to ~/.bashrc or ~/.zshrc"
