GO     ?= go
GARBLE ?= garble

.PHONY: cli cli-garble masker all clean

cli:
	$(GO) build -o maskkit ./cmd/maskkit

cli-garble:
	$(GARBLE) -literals build -o maskkit ./cmd/maskkit

masker:
	$(MAKE) -C src/

all: masker cli

clean:
	rm -f maskkit build/masked.bin
	$(MAKE) -C src/ clean
