# libmpmovie: decodes the game's MPEG-1 movies with AVFoundation for the emulator's DirectShow layer.
CC      = clang
CFLAGS  = -fobjc-arc -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11
OUT     = ../build
FW      = -framework Foundation -framework AVFoundation -framework CoreMedia -framework CoreVideo \
          -framework Metal -framework QuartzCore
all: $(OUT)/libmpmovie.dylib

$(OUT)/libmpmovie.dylib: mpmovie.m
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) -dynamiclib -install_name @rpath/libmpmovie.dylib -o $@ mpmovie.m $(FW)

clean:
	rm -f $(OUT)/libmpmovie.dylib
.PHONY: all clean
