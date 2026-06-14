GO     ?= go
GARBLE ?= garble

LDFLAGS = -s -w

.PHONY: cli runner runner-garble ext bundle all clean

# Operator CLI (Linux)
cli:
	$(GO) build -o injectkit ./cmd/injectkit

# Standalone Windows EXE
runner:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build \
		-ldflags="$(LDFLAGS)" -o build/injectkit.exe ./runner

# Standalone Windows EXE with garble (obfuscated strings + symbols)
runner-garble:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GARBLE) -literals build \
		-ldflags="$(LDFLAGS)" -o build/injectkit.exe ./runner

# Cross-compile Sliver Extension DLL
ext:
	$(MAKE) -C c/inject
	@mkdir -p build
	@cp c/inject/inject.x64.dll build/

# Package DLL + manifest into Sliver extension tarball
bundle: ext
	./injectkit bundle --output build/inject-0.1.0.tar.gz

# Build everything
all: cli runner ext bundle

clean:
	rm -f injectkit build/injectkit.exe build/inject.x64.dll build/inject-0.1.0.tar.gz
	$(MAKE) -C c/inject clean
