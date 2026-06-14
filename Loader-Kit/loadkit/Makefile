GO     ?= go
GARBLE ?= garble

.PHONY: cli cli-garble ext bundle all clean

# Build the operator CLI
cli:
	$(GO) build -o loadkit ./cmd/loadkit

# Build operator CLI with garble symbol/string obfuscation
cli-garble:
	$(GARBLE) -literals build -o loadkit ./cmd/loadkit

# Cross-compile the Sliver Extension DLL (requires mingw-w64)
ext:
	$(MAKE) -C c/load
	@mkdir -p build
	@cp c/load/load.x64.dll build/

# Package DLL + manifest into Sliver extension tarball
bundle: ext
	./loadkit bundle --output build/load-0.1.0.tar.gz

# Build everything
all: cli ext bundle

clean:
	rm -f loadkit build/loadkit.exe build/load.x64.dll build/payload.enc build/load-0.1.0.tar.gz
	$(MAKE) -C c/load clean
