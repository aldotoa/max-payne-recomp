# run_init --probe: at frame 3, R_File::changeDirectory("no_such_dir_e3") on the game's R_File (rlmfc 0x1000fc60;
# the object is [[0x7ca954]], the exe's import of rlmfc's file-system pointer). It throws R_FileException, its own
# catch runs and rethrows, and nothing above catches it: an unhandled report is expected.
if i == 3:
    fs = e.rd32(e.rd32(0x7ca954))
    arg = e.alloc(32)
    e.wr(arg, b"no_such_dir_e3\0")
    n = e.native
    s0 = n.seh_stats() if n is not None and getattr(n, "c_seh", False) else None
    print("E3 probe: c_seh=%s R_File=0x%x" % (getattr(n, "c_seh", None), fs))
    head = e.rd32(mpemu.TEB)
    print("E3 probe: fs:[0] was 0x%x (the CRT start-up's frame, stale since run_init stopped at AfxWinMain): "
          "cleared for the call" % head)
    e.wr32(mpemu.TEB, 0xFFFFFFFF)
    try:
        r = e.call(0x1000fc60, arg, ecx=fs, cc="thiscall")
        print("E3 probe: returned 0x%x fatal=%s" % (r, e.fatal))
    except Exception as ex:
        print("E3 probe: raised %s: %s" % (type(ex).__name__, str(ex)[:300]))
    if s0 is not None:
        print("E3 probe: seh before %s after %s" % (s0, n.seh_stats()))
    if n is not None:
        print("E3 probe: guest calls %s" % n.fast_stats()["guest_calls"])
    for line in list(e.apilog)[-40:]:
        if "SEH" in line or "RaiseException" in line or "RtlUnwind" in line:
            print("E3 probe: apilog " + line[:300])
    raise SystemExit(0)
