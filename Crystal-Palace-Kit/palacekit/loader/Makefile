CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -DWIN_X64 -shared -Wall -Wno-pointer-arith -Wno-unused-variable -c
OUTDIR  = bin

.PHONY: all clean

all: $(OUTDIR) $(OUTDIR)/loader.x64.o \
     $(OUTDIR)/pico.x64.o $(OUTDIR)/hooks.x64.o \
     $(OUTDIR)/spoof.x64.o $(OUTDIR)/cfg.x64.o $(OUTDIR)/cleanup.x64.o

$(OUTDIR):
	mkdir -p $(OUTDIR)

# Unity build: all loader C sources in one COFF object.
# Eliminates MinGW's .refptr / ADDR64 cross-TU global indirection (PIC-incompatible).
$(OUTDIR)/loader.x64.o: src/unity.c src/services.c src/pico.c src/hooks.c \
                         src/mask.c src/spoof.c src/cfg.c src/cleanup.c \
                         src/loader.c src/loader.h src/services.h src/pico.h
	$(CC) $(CFLAGS) src/unity.c -o $@

# Individual objects for pico.spec (PICO sub-blob).
# These have no cross-TU global refs that matter at runtime (dead code paths only).
$(OUTDIR)/pico.x64.o:    src/pico.c    src/loader.h src/pico.h
	$(CC) $(CFLAGS) $< -o $@

$(OUTDIR)/hooks.x64.o:   src/hooks.c   src/loader.h
	$(CC) $(CFLAGS) $< -o $@

$(OUTDIR)/spoof.x64.o:   src/spoof.c   src/loader.h
	$(CC) $(CFLAGS) $< -o $@

$(OUTDIR)/cfg.x64.o:     src/cfg.c     src/loader.h
	$(CC) $(CFLAGS) $< -o $@

$(OUTDIR)/cleanup.x64.o: src/cleanup.c src/loader.h src/services.h
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(OUTDIR)/*.o $(OUTDIR)/*.bin
