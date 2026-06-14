CC     := x86_64-w64-mingw32-gcc
TARGET := inject.x64.dll

CFLAGS  := -Wall -Os -s \
            -fno-stack-protector \
            -fno-ident \
            -D_WIN32_WINNT=0x0601 \
            -DWIN32_LEAN_AND_MEAN

LDFLAGS := -shared \
            -Wl,--disable-runtime-pseudo-reloc \
            -lntdll

.PHONY: all clean

all: $(TARGET)

$(TARGET): inject.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
