BIN := bin
PKG := ./cmd/netdiag

.PHONY: build test vet dist clean run

build:
	go build -o $(BIN)/netdiag $(PKG)

run: build
	./$(BIN)/netdiag

test:
	go test ./...

vet:
	go vet ./...
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...

# macOS builds use cgo for CoreWLAN (Wi-Fi signal stats), so they must be
# built on a Mac. Linux and Windows builds are pure Go.
dist:
	mkdir -p $(BIN)/dist
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o $(BIN)/dist/netdiag-darwin-arm64 $(PKG)
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $(BIN)/dist/netdiag-darwin-amd64 $(PKG)
	lipo -create -output $(BIN)/dist/netdiag-macos-universal $(BIN)/dist/netdiag-darwin-arm64 $(BIN)/dist/netdiag-darwin-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BIN)/dist/netdiag-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BIN)/dist/netdiag-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BIN)/dist/netdiag-windows-amd64.exe $(PKG)

clean:
	rm -rf $(BIN)
