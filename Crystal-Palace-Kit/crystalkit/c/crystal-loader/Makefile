CC     := x86_64-w64-mingw32-gcc
CFLAGS := -Wall -Os -DBUILD_DLL -ffunction-sections -fdata-sections
LFLAGS := -shared -Wl,--subsystem,windows -s -Wl,--gc-sections

TARGET := crystal-loader.x64.dll
SRCS   := crystal-loader.c beacon_compatibility.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LFLAGS)

clean:
	rm -f $(TARGET)
