# libmprender (Metal renderer for the D3D8 command stream) and the mpreplay tool. Needs only the Command Line
# Tools: shaders are compiled at runtime.
CC      = clang
CFLAGS  = -fobjc-arc -O2 -Wall -Wextra -Wno-unused-parameter -std=gnu11
OUT     = ../build
FW      = -framework Foundation -framework Metal -framework QuartzCore -framework AppKit
all: $(OUT)/libmprender.dylib $(OUT)/mpreplay

$(OUT)/shaders.inc: shaders.metal
	@mkdir -p $(OUT)
	xxd -i < shaders.metal > $@

$(OUT)/libmprender.dylib: mprender.m mprender.h $(OUT)/shaders.inc
	$(CC) $(CFLAGS) -I$(OUT) -dynamiclib -install_name @rpath/libmprender.dylib -o $@ mprender.m $(FW)

$(OUT)/mpreplay: mpreplay.m mprender.h $(OUT)/libmprender.dylib
	$(CC) $(CFLAGS) -o $@ mpreplay.m -L$(OUT) -lmprender -Wl,-rpath,@executable_path \
	    -framework Foundation -framework ImageIO -framework CoreGraphics -framework UniformTypeIdentifiers

clean:
	rm -f $(OUT)/libmprender.dylib $(OUT)/mpreplay $(OUT)/shaders.inc
.PHONY: all clean
