# JSHunter developer tasks. Mirrors the checks run in CI (.github/workflows/ci.yml).
# Recipes are tab-indented as make requires.

BINARY       := jshunter
CMD          := ./cmd/jshunter
PKGS         := ./...
SRC_DIRS     := cmd internal
COVERPROFILE := coverage.out

.PHONY: all build test vet fmt lint selftest cover clean help

## all: format-agnostic default — build the binary.
all: build

## build: compile the CLI into ./bin.
build:
	go build -o bin/$(BINARY) $(CMD)

## test: run the full suite with the race detector.
test:
	go test $(PKGS) -race

## vet: run go vet across every package.
vet:
	go vet $(PKGS)

## fmt: rewrite Go sources in canonical gofmt style.
fmt:
	gofmt -w $(SRC_DIRS)

## lint: run golangci-lint (see .golangci.yml).
lint:
	golangci-lint run

## selftest: exercise the rule registry against its built-in TP/FP fixtures.
selftest:
	go run $(CMD) --self-test

## cover: produce a coverage profile and print the total.
cover:
	go test $(PKGS) -covermode=atomic -coverprofile=$(COVERPROFILE)
	go tool cover -func=$(COVERPROFILE) | tail -n 1

## clean: remove build and coverage artifacts.
clean:
	rm -rf bin $(COVERPROFILE)
	go clean

## help: list the available targets.
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
