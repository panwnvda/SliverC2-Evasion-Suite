GO     ?= go
GARBLE ?= garble

.PHONY: cli cli-garble loader all clean

# Build the operator CLI
cli:
	$(GO) build -o palacekit ./cmd/palacekit

# Build operator CLI with garble symbol/string obfuscation
cli-garble:
	$(GARBLE) -literals build -o palacekit ./cmd/palacekit

# Cross-compile the COFF loader objects (requires mingw-w64)
loader:
	$(MAKE) -C loader/

# Build everything
all: cli loader

clean:
	rm -f palacekit build/palace.bin
	$(MAKE) -C loader/ clean
