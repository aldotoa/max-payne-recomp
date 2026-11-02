# libmpaudio: the software mixer behind the emulator's DirectSound layer. Needs SDL3 (Homebrew).
CC      = clang
CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11
SDL    ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
OUT     = ../build
all: $(OUT)/libmpaudio.dylib

$(OUT)/libmpaudio.dylib: mpaudio.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -I$(SDL)/include -dynamiclib -install_name @rpath/libmpaudio.dylib -o $@ mpaudio.c \
	    -L$(SDL)/lib -lSDL3 -Wl,-rpath,$(SDL)/lib

clean:
	rm -f $(OUT)/libmpaudio.dylib
.PHONY: all clean
