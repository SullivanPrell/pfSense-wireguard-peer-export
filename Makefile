# pfSense WG Suite -- hardened fork
#
# The package is built by build.py using only the Python standard library,
# so `make` works on macOS and Linux as well as FreeBSD.

PKG_NAME    := pfSense-pkg-wg-export
PKG_VERSION := $(shell python3 -c "import json;print(json.load(open('pkg/metadata.json'))['version'])")
PKG         := dist/$(PKG_NAME)-$(PKG_VERSION).pkg

BASE_VERSION := 1.1.0

.PHONY: all build list verify check lint callgraph render test clean help

all: build

## build: produce dist/<name>-<version>.pkg
build:
	@python3 build.py

## list: show every file that would be packaged, with hashes
list:
	@python3 build.py --list

## verify: confirm the built package matches the src/ tree
verify: $(PKG)
	@python3 build.py --verify $(PKG)

## check: compare src/ structure against the upstream package it forked from
check:
	@base=$$(python3 tools/extract-upstream.py $(BASE_VERSION)); \
	python3 tools/phpbalance.py --baseline $$base/usr/local src/usr/local; \
	rc=$$?; rm -rf "$$base"; exit $$rc

## lint: PHP syntax-check every source file (requires php)
lint:
	@command -v php >/dev/null || { echo "php not installed; skipping"; exit 0; }
	@fail=0; for f in $$(find src -name '*.php'); do \
		php -l "$$f" >/dev/null 2>&1 || { echo "SYNTAX ERROR: $$f"; fail=1; }; \
	done; \
	if [ $$fail -eq 0 ]; then echo "all PHP files parse cleanly"; fi; \
	exit $$fail

## callgraph: prove no call site references a function this fork removed (needs php)
callgraph:
	@command -v php >/dev/null || { echo "php not installed; skipping"; exit 0; }
	@base=$$(python3 tools/extract-upstream.py $(BASE_VERSION)); \
	python3 tools/callgraph.py src "$$base"; \
	rc=$$?; rm -rf "$$base"; exit $$rc

## render: execute every page against a stub pfSense, diff output vs upstream (needs php)
render:
	@command -v php >/dev/null || { echo "php not installed; skipping"; exit 0; }
	@base=$$(python3 tools/extract-upstream.py $(BASE_VERSION)); \
	python3 tools/render-check/drive.py src "$$base"; \
	rc=$$?; rm -rf "$$base"; exit $$rc

## test: run every check — lint, structure, call graph, render
test: lint check callgraph render

## clean: remove build output
clean:
	@rm -rf dist

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
