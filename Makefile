.PHONY: test run fmt
fmt:
	gofmt -w $(shell find . -name '*.go')
test:
	go test ./...
run:
	go run ./cmd/geodns
