.PHONY: ci fmt-check vet tidy-check build test

ci: fmt-check vet tidy-check build test

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...
	go vet -tags perrytest ./...

tidy-check:
	@cp go.mod go.mod.tidy-bak; cp go.sum go.sum.tidy-bak 2>/dev/null || true
	@go mod tidy; \
	if ! diff -q go.mod go.mod.tidy-bak >/dev/null || { [ -f go.sum.tidy-bak ] && ! diff -q go.sum go.sum.tidy-bak >/dev/null; }; then \
	  mv go.mod.tidy-bak go.mod; mv go.sum.tidy-bak go.sum 2>/dev/null; echo "go mod tidy needed"; exit 1; fi; \
	rm -f go.mod.tidy-bak go.sum.tidy-bak

build:
	go build -o bin/perry ./cmd/perry

test:
	go test ./...
