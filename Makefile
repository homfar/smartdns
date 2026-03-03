.PHONY: fmt fmt-check test verify run

fmt:
	gofmt -w $(shell rg --files -g '*.go')

fmt-check:
	@test -z "$(gofmt -l $(shell rg --files -g '*.go'))"

test:
	go test ./...

verify: fmt-check
	go vet ./...
	go test ./...
	go test -race ./...
	staticcheck ./...

run:
	go run ./cmd/geodns
