.PHONY: fmt fmt-check test test-race verify run

fmt:
	gofmt -w $(shell rg --files -g '*.go')

fmt-check:
	@test -z "$(gofmt -l $(shell rg --files -g '*.go'))"

test:
	go test ./...

test-race:
	go test -race ./...

verify: fmt-check
	go vet ./...
	go test ./...
	go test -race ./...
	staticcheck ./...

run:
	go run ./cmd/geodns
