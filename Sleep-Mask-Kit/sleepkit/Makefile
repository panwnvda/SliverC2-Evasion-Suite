GO ?= go

.PHONY: cli cli-garble clean

# Build the operator CLI
cli:
	$(GO) build -o sleepkit ./cmd/sleepkit

# Build operator CLI with garble
cli-garble:
	garble -literals build -o sleepkit ./cmd/sleepkit

clean:
	rm -f sleepkit build/mask.exe build/payload.enc
