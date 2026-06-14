CC     = x86_64-w64-mingw32-gcc
CFLAGS = -DWIN_X64 -shared -Wall -Wno-pointer-arith -Wno-unused-variable -c
OUTDIR = ../bin

.PHONY: all clean

all: $(OUTDIR) $(OUTDIR)/masker.x64.o

$(OUTDIR):
	mkdir -p $(OUTDIR)

# Unity build: compile all C sources into a single COFF object.
# This eliminates MinGW's .refptr / ADDR64 cross-TU indirection which is
# incompatible with PIC shellcode (absolute addresses unknown at link time).
$(OUTDIR)/masker.x64.o: unity.c services.c mask.c hook.c masker.c masker.h
	$(CC) $(CFLAGS) unity.c -o $@

clean:
	rm -f $(OUTDIR)/*.o
