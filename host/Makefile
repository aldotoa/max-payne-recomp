# mphost: the native host (E5). Runs a lifted library (lift/build.py) with no emulator: mphost GAME_DIR --lib LIB.
CC      = clang
SDL    ?= $(shell brew --prefix 2>/dev/null || echo /opt/homebrew)
CFLAGS  = -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11 -I../lift/runtime -I$(SDL)/include
OUT     = ../build
SRC     = mphost.c hle_kernel32.c hle_files.c hle_user32.c hle_winsys.c hle_advapi32.c hle_d3d8.c hle_dshow.c hle_dinput.c hle_dsound.c live.c
all: $(OUT)/mphost

$(OUT)/libmpmovie.dylib:
	$(MAKE) -C ../movie

$(OUT)/libmprender.dylib:
	$(MAKE) -C ../render

$(OUT)/libmpaudio.dylib:
	$(MAKE) -C ../audio

$(OUT)/mphost: $(SRC) $(OUT)/libmpmovie.dylib $(OUT)/libmprender.dylib $(OUT)/libmpaudio.dylib host.h crt_check.inc ../lift/runtime/cpu.h ../lift/runtime/runtime.h
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -o $@ $(SRC) -L$(OUT) -lmpmovie -lmprender -lmpaudio -lz -lobjc -L$(SDL)/lib -lSDL3 \
		-Wl,-rpath,@executable_path -Wl,-rpath,$(SDL)/lib

clean:
	rm -f $(OUT)/mphost
.PHONY: all clean
