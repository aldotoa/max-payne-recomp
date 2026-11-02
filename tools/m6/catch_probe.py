# run_init --probe (E3): a real throw and catch in the game. At frame 3, call the exe's 0x4109c0 (thiscall; [this+4] is
# a file name, [this+8] nonzero): for a .mps file that exists it builds an R_MemoryFile and opens its first chunk inside
# try { } catch (...) { }. The file here is garbage, so rlmfc throws while reading it and the exe catches it and returns.
# Prints the result, e.fatal, and seh.c's counters (raises handled in C) when the library serves them; the run goes on
# afterwards, so later frames show the game is still sound.
if i == 3:
    import os
    path = mpemu.host_write_path(e, "C:\\MaxPayne\\e3_garbage.mps")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(bytes((k * 37 + 11) & 0xFF for k in range(4096)))
    name = e.alloc(64)
    e.wr(name, b"e3_garbage.mps\0")
    obj = e.alloc(16)
    e.wr32(obj + 4, name)
    e.wr32(obj + 8, 1)
    n = e.native
    seh = n is not None and getattr(n, "c_seh", False)
    s0 = n.seh_stats() if seh else None
    head = e.rd32(mpemu.TEB)
    try:
        r = e.call(0x4109c0, ecx=obj)
        print("E3 catch: returned 0x%x fatal=%s fs:[0] before 0x%x after 0x%x" % (r, e.fatal, head, e.rd32(mpemu.TEB)))
    except Exception as ex:
        print("E3 catch: raised %s: %s" % (type(ex).__name__, str(ex)[:300]))
    if seh:
        s1 = n.seh_stats()
        print("E3 catch: seh.c raises %d unwinds %d handled %d (depth max %d)" % (
            s1["raises"] - s0["raises"], s1["unwinds"] - s0["unwinds"], s1["handled"] - s0["handled"], s1["depth"]))
    for line in list(e.apilog)[-60:]:
        if "SEH raise" in line or "thrown" in line:
            print("E3 catch: apilog " + line[:260])
