# run_init --probe file: PC-sample the main thread from frame PCS_FROM to frame PCS_TO (environment, defaults 400 and
# 1250) into PCS_OUT (default lift-out/pcsample.txt) with build/libpcsample.dylib (tools/m6/pcsample.c, H54).
# The probe runs once per frame with i in scope; the library handle is kept in builtins between frames.
import builtins, ctypes, os
if not hasattr(builtins, "_pcs"):
    builtins._pcs = ctypes.CDLL(os.path.abspath("build/libpcsample.dylib"))
    builtins._pcs.pcs_start.argtypes = [ctypes.c_uint32]
    builtins._pcs.pcs_stop.argtypes = [ctypes.c_char_p]
if i == int(os.environ.get("PCS_FROM", 400)):
    builtins._pcs.pcs_start(int(os.environ.get("PCS_PERIOD_US", 500)))
    print("  pcsample: started")
if i == int(os.environ.get("PCS_TO", 1250)):
    n = builtins._pcs.pcs_stop(os.environ.get("PCS_OUT", "lift-out/pcsample.txt").encode())
    print("  pcsample: %d samples" % n)
