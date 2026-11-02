"""Skip MFC's AfxWinMain: after the exe's CRT/static constructors, call CMaxPayneApp::InitInstance directly.
--real-entry runs the game from its entry point instead (E4, docs/m6-emu-removal.md)."""
import bisect, collections, json, os, struct, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
import mpemu
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_ECX, UC_X86_REG_ESP, UC_X86_REG_EAX

game = sys.argv[1] if len(sys.argv) > 1 else "Max Payne"
e = mpemu.boot(game, with_exe=True)
exe = e.modules["maxpayne.exe"]
# Per-user data (registry, saved games, files the game writes): --data-dir DIR, default
# ~/Library/Application Support/Max Payne Recomp (mpemu.data_dir).
if '--data-dir' in sys.argv:
    e.data_dir = sys.argv[sys.argv.index('--data-dir') + 1]
# Native launcher options in place of the startup dialog (emu/launcher.py): the saved video settings the game needs
# to skip the dialog, --resolution, --set, --fullscreen/--windowed, --game-mode; the command line with -nodialog
# (maxpayne.exe+0x40cb90 is CMaxPayneCommandLine::ParseParam). --settings prints them and exits.
import launcher
host = launcher.configure(mpemu, e, sys.argv)
if '--settings' in sys.argv:
    launcher.print_settings(mpemu, e)
    raise SystemExit(0)
# Sound: --audio device|null|off (default: device with --window, off otherwise; "null" mixes at the real-time
# rate without playing), --audio-wav FILE writes the mixed output (emu/dsound.py, audio/).
e.audio = sys.argv[sys.argv.index('--audio') + 1] if '--audio' in sys.argv else ("device" if '--window' in sys.argv else None)
if e.audio == "off":
    e.audio = None
e.audio_record = sys.argv[sys.argv.index('--audio-wav') + 1] if '--audio-wav' in sys.argv else None
if e.audio_record and not e.audio:
    e.audio = "null"
# Intro movie (played by InitInstance through DirectShow, emu/dshow.py): --intro play|skip. Default: play with
# --window; headless runs skip it by pressing a key when it starts, as a player would.
e.intro = sys.argv[sys.argv.index('--intro') + 1] if '--intro' in sys.argv else ("play" if '--window' in sys.argv else "skip")
if '--hook' in sys.argv:
    from unicorn import UC_HOOK_CODE
    for hv in sys.argv[sys.argv.index('--hook') + 1].split(','):
        va = int(hv, 16)
        def _h(uc, address, size, user, _va=va):
            print("HOOK hit %s  eax=0x%x ecx=0x%x esp=0x%x ret=%s" % (e.module_at(address), uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ECX),
                  uc.reg_read(UC_X86_REG_ESP), e.module_at(e.rd32(uc.reg_read(UC_X86_REG_ESP)))))
        e.uc.hook_add(UC_HOOK_CODE, _h, begin=va, end=va)
assert mpemu.run_dll_mains(e, verbose=False), "DLL init failed"

# --record-entries PATH: the maxpayne.exe .text addresses entered by a call instruction (direct or indirect, from any
# loaded module) or reached by an indirect jmp, with counts, from here through the end of the run (JSON at PATH, written
# at the end). A capstone pass over the loaded modules' code finds the call and indirect-jmp instructions; one UC_HOOK_BLOCK
# on all code then matches each block to the instruction that ended the block before it. Cost: one Python callback per
# translated block executed (about 24x slower over the 80-frame workload).
rec_hits = rec_sites = None
if '--record-entries' in sys.argv:
    import capstone
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    from unicorn import UC_HOOK_BLOCK
    import unicorn.x86_const as xc
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    rec_sites = {}          # instruction address -> (is_call, ("imm", target) | ("reg", reg) | ("mem", base, index, scale, disp))
    rec_end_of = {}         # the same instruction addresses -> the address just after the instruction
    rec_seg = 0             # indirect operands with a segment prefix (not decoded)
    def _sweep(code, lo, stats):
        # capstone stops at the first undecodable byte: resume one byte later, so data inside code does not end the sweep
        pos = 0
        while pos < len(code):
            for ins in md.disasm(code[pos:], lo + pos):
                pos = ins.address - lo + ins.size
                stats["insns"] += 1
                stats["insn_bytes"] += ins.size
                yield ins
            if pos < len(code):
                stats["restarts"] += 1
                stats["skipped"] += 1
                pos += 1
    sweep_stats = []            # (module, section, section size, stats) for the report
    for mod in e.modules.values():
        for sec in mod.pe.sections:
            # maxpayne.exe's code sections are not flagged executable in its PE header, so take them by name too
            name = sec.Name.rstrip(b"\0").decode("ascii", "replace")
            if not (sec.Characteristics & 0x20000000 or name.startswith((".text", "stxt", ".MGD"))):
                continue
            lo = mod.base + sec.VirtualAddress
            code = e.rd(lo, max(sec.Misc_VirtualSize, sec.SizeOfRawData))
            st = collections.Counter()
            for ins in _sweep(code, lo, st):
                if ins.mnemonic not in ("call", "jmp") or not ins.operands:
                    continue
                is_call, op = ins.mnemonic == "call", ins.operands[0]
                rec_end_of[ins.address] = ins.address + ins.size
                if op.type == X86_OP_IMM:
                    if is_call:
                        rec_sites[ins.address] = (True, ("imm", op.imm))
                elif op.type == X86_OP_REG:
                    rec_sites[ins.address] = (is_call, ("reg", getattr(xc, "UC_X86_REG_" + ins.reg_name(op.reg).upper())))
                elif op.type == X86_OP_MEM:
                    m = op.mem
                    if m.segment:
                        rec_seg += 1
                        continue
                    rec_sites[ins.address] = (is_call, ("mem", getattr(xc, "UC_X86_REG_" + ins.reg_name(m.base).upper()) if m.base else None,
                                                        getattr(xc, "UC_X86_REG_" + ins.reg_name(m.index).upper()) if m.index else None,
                                                        m.scale, m.disp))
            sweep_stats.append((mod.name, name, len(code), st))
    # One block hook for all code, not one hook per site: Unicorn walks its whole hook list on every translated block,
    # and ~18,000 per-site hooks stalled the run (Unicorn 2.1.4 also rejects UC_HOOK_INSN for call and jmp). A translated
    # block ends at a call or jmp, so the block after one starts at its target. The previous block's end address names
    # the instruction that ended it; for a call, [esp] must hold that instruction's return address (this rejects host
    # returns from stubs that land after a call). Indirect jmps are not checked this way: their target is the next block.
    rec_ends = {end: site for site, end in rec_end_of.items() if site in rec_sites}     # instruction end -> its address
    rec_hits = collections.Counter()        # (site, target) -> executions
    rec_mismatch = [0]                      # direct calls whose block did not start at the operand's target
    rec_jmp_drop = [0]                      # indirect jmps whose target did not equal the operand value (false sites)
    rec_prev = [None]                       # end address of the previous block
    def _operand(uc, d):
        # value of an operand, read now: a jmp changes no register or memory, so this is the value it jumped with
        if d[0] == "imm": return d[1]
        if d[0] == "reg": return uc.reg_read(d[1])
        _, b, x, sc, disp = d
        ea = (disp + (uc.reg_read(b) if b else 0) + (uc.reg_read(x) * sc if x else 0)) & 0xFFFFFFFF
        return struct.unpack("<I", bytes(uc.mem_read(ea, 4)))[0]
    def _rec_block(uc, address, size, user):
        end, rec_prev[0] = rec_prev[0], address + size
        site = rec_ends.get(end)
        if site is None:
            return
        is_call, d = rec_sites[site]
        try:
            if is_call:
                if struct.unpack("<I", bytes(uc.mem_read(uc.reg_read(UC_X86_REG_ESP), 4)))[0] != end:
                    return
                if d[0] == "imm" and d[1] != address:
                    rec_mismatch[0] += 1
            elif _operand(uc, d) != address:
                rec_jmp_drop[0] += 1
                return
        except Exception:
            return
        rec_hits[(site, address)] += 1
    e.uc.hook_add(UC_HOOK_BLOCK, _rec_block)
    e.uc.ctl_flush_tb()         # hooks only reach code translated after they are added
    print("record-entries: %d call / indirect-jmp sites in %d modules (%d segment-prefixed indirect operands not decoded)" % (
        len(rec_sites), len(e.modules), rec_seg))
    print("record-entries: sweep coverage per section (instruction bytes / section bytes; undecodable bytes skipped in restarts):")
    _by_mod = collections.OrderedDict()
    for _m, _s, _n, _st in sweep_stats:
        _mm = _by_mod.setdefault(_m, [0, 0, 0, 0, 0])
        _mm[0] += _n; _mm[1] += _st["insn_bytes"]; _mm[2] += _st["skipped"]; _mm[3] += _st["restarts"]; _mm[4] += _st["insns"]
        print("   %-14s %-9s %9d bytes, %9d in %8d insns (%5.1f%%), %6d skipped in %5d restarts" % (
            _m, _s, _n, _st["insn_bytes"], _st["insns"], 100.0 * _st["insn_bytes"] / max(_n, 1), _st["skipped"], _st["restarts"]))
    for _m, _mm in _by_mod.items():
        print("   %-14s total %9d bytes, %9d in instructions (%5.1f%%), %6d skipped in %5d restarts" % (
            _m, _mm[0], _mm[1], 100.0 * _mm[1] / max(_mm[0], 1), _mm[2], _mm[3]))

# Lifted rlmfc.dll (M5, emu/native.py). --native-lift LIB: every lifted function is patched to run natively (no
# comparison). --diff-lift LIB (a library built with lift/build.py --write-log): differential mode, the first
# --diff-k calls (default 20) of each lifted function run emulated and natively from the same state and are compared;
# the game continues with the emulated result. --diff-report PATH writes the report as JSON at the end.
# --diff-budget N: guest instructions one reference run may execute (default native.DIFF_BUDGET, 20,000,000; 0 for
# unlimited). A run over the budget is rolled back and the function runs emulated from then on (retired too long).
# --diff-only HEX,... (or --diff-only-file PATH: one hex VA per line, '#' comments) limits the differential mode to the
# given functions: each is diffed when emulated code calls it, and everything else runs emulated. Every VA must be a
# lifted real function entry, or the run exits listing the bad ones. Without these flags the diff covers all real
# entries, as before.
#
# --native-lift LIB dispatches through the fast path (native.install_fast: the calls run from a C code hook inside
# emu_start). --native-lift-slow LIB is the bridge without it (every native call stops emu_start; native.install).
# Calls from lifted code to MSVCRT's _ftol and tolower run native helpers (lift/runtime/crt.c) unless --no-native-crt.
# Calls from lifted code through a register or memory that reach an import thunk (`jmp [iat]`, never lifted) go straight
# to the thunk's target (runtime.c call_fill) unless --no-thunk-shortcut, which keeps them as guest calls (for comparison).
# Calls from lifted code to the HLE handlers in mpemu.HLE_DIRECT (QueryPerformanceCounter, D3D8) run the handler without
# the emulator (runtime.c hle_direct) unless --no-hle-direct. The main loop's direct calls are reported by handler time:
# the top 20, or --hle-top N. With direct calls, the guest heap moves to C when the fast path starts (lift/runtime/heap.c)
# and lifted code's HeapAlloc/HeapFree calls are served there, unless --no-c-heap. Run-time call targets from lifted code
# are resolved once and cached (runtime.c call_resolve) unless --no-call-cache. QueryPerformanceCounter and the hot D3D8
# methods (render and texture-stage states, SetTexture, streams, indices, buffer locks, DrawIndexedPrimitive) are served
# in C (lift/runtime/hle_fast.c) unless --no-c-hle.
# The fast path prints the main loop's guest calls from native code by target: the top 15, or --guest-top N.
# It also prints the main loop's fast-path entries by caller (the return address of the call into a native slot), per
# module and the top 25, or --caller-top N.
native = None
_loader = None                  # native.LiftLoader (the lifted modules; its load hook stays registered on e)
if ('--diff-only' in sys.argv or '--diff-only-file' in sys.argv) and '--diff-lift' not in sys.argv:
    raise SystemExit("--diff-only and --diff-only-file need --diff-lift LIB")
if '--diff-lift' in sys.argv or '--native-lift' in sys.argv or '--native-lift-slow' in sys.argv:
    import native as native_mod
    _lift_opt = '--diff-lift' if '--diff-lift' in sys.argv else ('--native-lift' if '--native-lift' in sys.argv else '--native-lift-slow')
    _lift_lib = sys.argv[sys.argv.index(_lift_opt) + 1]
    native = native_mod.Native(e, _lift_lib, crt='--no-native-crt' not in sys.argv,
                               thunk_shortcut='--no-thunk-shortcut' not in sys.argv,
                               hle_direct='--no-hle-direct' not in sys.argv,
                               c_heap='--no-c-heap' not in sys.argv,
                               call_cache='--no-call-cache' not in sys.argv,
                               c_hle='--no-c-hle' not in sys.argv)
    # --lift-modules: the modules the library was built from (lift/build.py --module), default rlmfc.dll. Each has its
    # inventory, lift-out/<stem>_functions.json, unless --diff-inventory gives them (a comma-separated list, in the same
    # order as the modules).
    _mods = [m.strip() for m in sys.argv[sys.argv.index('--lift-modules') + 1].split(',') if m.strip()] \
        if '--lift-modules' in sys.argv else ["rlmfc.dll"]
    _root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    _invs = sys.argv[sys.argv.index('--diff-inventory') + 1].split(',') if '--diff-inventory' in sys.argv else \
        [os.path.join(_root, "lift-out", os.path.splitext(m)[0] + "_functions.json") for m in _mods]
    if len(_invs) != len(_mods):
        raise SystemExit("--diff-inventory has %d files for %d --lift-modules" % (len(_invs), len(_mods)))
    # Only real function entries are hooked or patched: a gap-scan find that no function calls is a label inside another
    # function (see native.function_entries). The inventories: lift/functions.py writes lift-out/<stem>_functions.json.
    _real = set()
    for _inv in _invs:
        _real |= native_mod.function_entries(_inv)
    print("lifted entries: %d; real function entries among them: %d" % (
        len(native.table), len(_real & set(native.table))))
    # A module of --lift-modules that is not loaded at setup (e.g. a DLL the game loads with LoadLibraryA) is deferred:
    # native.LiftLoader installs its entries when it loads (the load hook, Emu.on_module_loaded), checking its base.
    # Its inventory is read now (its entries count in _real for the --diff-only check).
    _deferred = [m for m in _mods if e.find_module(m) is None]
    if _deferred:
        print("lifted modules deferred to their load: %s" % ", ".join(_deferred))
    if '--diff-lift' in sys.argv:
        # --diff-only HEX,... / --diff-only-file PATH: diff only these functions (each one when emulated code calls it),
        # instead of every real entry. Everything else runs emulated, so a function hidden behind a diverging caller is
        # reachable. Every VA must be a lifted real function entry.
        _diff_set = _real
        if '--diff-only' in sys.argv or '--diff-only-file' in sys.argv:
            _vas = set()
            try:
                if '--diff-only' in sys.argv:
                    _vas |= native_mod.parse_va_text(sys.argv[sys.argv.index('--diff-only') + 1])
                if '--diff-only-file' in sys.argv:
                    with open(sys.argv[sys.argv.index('--diff-only-file') + 1]) as _fh:
                        _vas |= native_mod.parse_va_text(_fh.read())
            except ValueError as _err:
                raise SystemExit("--diff-only: %s" % _err)
            if not _vas:
                raise SystemExit("--diff-only: no VAs given")
            _bad = sorted(va for va in _vas if va not in native.table or va not in _real)
            if _bad:
                raise SystemExit("--diff-only: %d VA(s) are not lifted real function entries: %s" % (
                    len(_bad), ", ".join("0x%08x" % va for va in _bad)))
            _diff_set = _vas
            print("diff only: %d functions" % len(_diff_set))
        native.enable_diff(k=int(sys.argv[sys.argv.index('--diff-k') + 1]) if '--diff-k' in sys.argv else 20,
                           only=set(),
                           budget=int(sys.argv[sys.argv.index('--diff-budget') + 1]) if '--diff-budget' in sys.argv
                           else native_mod.DIFF_BUDGET)
        _loader = native_mod.LiftLoader(native, "diff", diff_only=_diff_set)
    else:
        _loader = native_mod.LiftLoader(native, "fast" if _lift_opt == '--native-lift' else "slow")
    for _m, _inv in zip(_mods, _invs):
        _loader.add(_inv, e.find_module(_m))           # loaded now: installed now; else at its load
    if '--diff-lift' in sys.argv:
        print("differential mode: %d lifted entries hooked at setup" % _loader.count)
    else:
        print("native mode (%s): %d lifted functions installed at setup (patched entries)" % (
            "fast dispatch" if _lift_opt == '--native-lift' else "slow bridge", _loader.count))

# --real-entry (E4): run the game's own start-up and loop instead of calling InitInstance and the frame function from
# here (see the main loop below).
REAL = '--real-entry' in sys.argv
if REAL and native is not None and not native._fast:
    raise SystemExit("--real-entry runs under the emulator or with --native-lift (not --diff-lift or --native-lift-slow)")
if not REAL and native is not None and exe.entry in native.installed:
    # the stop at AfxWinMain is a code hook: lifted start-up code runs past it into the game's own loop
    raise SystemExit("the library lifts the exe entry point 0x%x (H63 and later): run with --real-entry, or use a "
                     "library built with --keep-emulated 0x783860,0x76fb04" % exe.entry)
# --guest-blocks: count the guest code the emulator runs inside the loaded modules (E4's check that none is left):
# each translated block executed in a module image, but for the patched entries of lifted functions (the jump into a
# native slot). HLE stubs and the host's own trampolines are outside the images. Reported at the end of the run.
guest_blocks = None
if '--guest-blocks' in sys.argv:
    from unicorn import UC_HOOK_BLOCK
    guest_blocks = collections.Counter()
    _gb_ranges = []

    def _gb_hook(uc, address, size, user):
        if native is not None and address in native.installed:
            return
        if len(_gb_ranges) != len(e.modules):              # a module loaded since (LoadLibraryA)
            _gb_ranges[:] = [(m.base, m.base + m.size) for m in e.modules.values()]
        if any(lo <= address < hi for lo, hi in _gb_ranges):
            guest_blocks[address] += 1
    e.uc.hook_add(UC_HOOK_BLOCK, _gb_hook)
    e.uc.ctl_flush_tb()         # hooks only reach code translated after they are added
if not REAL:
    afx_va = e.modules["mfc42.dll"].ord_exports[1576]      # AfxWinMain, the exe's WinMain target
    e.stop_at(afx_va, "AfxWinMain")
    e.call(exe.entry, timeout=600)
    assert e.fatal and "AfxWinMain" in e.fatal, e.fatal
    print("CRT + static constructors done:", e.fatal)

    # find the global CMaxPayneApp: the object whose first dword is the CMaxPayneApp vtable (0x7cb77c)
    VT = 0x7cb77c
    dat = next(s for s in exe.pe.sections if s.Name.startswith(b".data"))
    lo = exe.base + dat.VirtualAddress
    blob = e.rd(lo, dat.Misc_VirtualSize)
    hits = [lo + i for i in range(0, len(blob) - 3, 4) if struct.unpack_from("<I", blob, i)[0] == VT]
    print("objects with CMaxPayneApp vtable:", [hex(h) for h in hits])
    app = hits[0]

    print("file-system calls during DLL init + static-ctor phase:")
    for l in e.apilog:
        if any(k in l for k in ("FindFirst", "FindNext", "FindClose", "CreateFile", "GetFileAttr", "SetCurrentDir", "GetCurrentDir", "GetFullPath", "GetModuleFileName")):
            print("  ", l[:170])
    rl = e.modules["rlmfc.dll"]
    print("rlmfc Sys (R_System*): 0x%x" % e.rd32(rl.exports["?Sys@@3PAVR_System@@A"]))
    print("rlmfc R_File::RASArchiveList: 0x%x" % e.rd32(rl.exports["?RASArchiveList@R_File@@0PAV?$R_DLList@UR_RASArchive@R_File@@@@A"]))
e.apilog.clear(); e.mfc_calls.clear()
if '--trace' in sys.argv: e.enable_pc_trace(40)
if '--strhook' in sys.argv:
    from unicorn import UC_HOOK_CODE
    from unicorn.x86_const import UC_X86_REG_EDI
    va = int(sys.argv[sys.argv.index('--strhook') + 1], 16)
    def _sh(uc, address, size, user):
        def s(p):
            try: return e.cstr(p, 80)
            except Exception: return "?"
        print("STRHOOK %s  eax=0x%x %r   edi=0x%x %r" % (e.module_at(address), uc.reg_read(UC_X86_REG_EAX), s(uc.reg_read(UC_X86_REG_EAX)), uc.reg_read(UC_X86_REG_EDI), s(uc.reg_read(UC_X86_REG_EDI))))
    e.uc.hook_add(UC_HOOK_CODE, _sh, begin=va, end=va)
if '--watch' in sys.argv:
    from unicorn import UC_HOOK_MEM_WRITE
    wa = int(sys.argv[sys.argv.index('--watch') + 1], 16)
    def _w(uc, access, address, size, value, user):
        print("WATCH write 0x%x <- 0x%x (size %d) from %s" % (address, value & 0xFFFFFFFF, size, e.module_at(uc.reg_read(UC_X86_REG_EIP))))
    e.uc.hook_add(UC_HOOK_MEM_WRITE, _w, begin=wa, end=wa + 3)
t = time.time()
# Budgets are host seconds (--timeout, --frame-slice), not instruction counts: an instruction count makes Unicorn
# run a counting hook on every instruction, which made the whole emulator 5-20x slower. --cap N still sets an
# instruction budget for InitInstance when an exact count matters.
CAP = int(float(sys.argv[sys.argv.index('--cap') + 1])) if '--cap' in sys.argv else 0
TIMEOUT = float(sys.argv[sys.argv.index('--timeout') + 1]) if '--timeout' in sys.argv else 1200
if '--window' in sys.argv:          # open the window now: the intro movie plays during InitInstance
    import live as live_mod
    live_mod.LiveView(e)


def init_report(r):
    """What InitInstance did (r: its result), and the usage reports so far."""
    print("InitInstance returned eax=%d after %.1fs: %s" % (r, time.time() - t, e.fatal or "no fault"))
    print("at:", e.where(), "->", e.module_at(e.uc.reg_read(UC_X86_REG_EIP)))
    if e.fatal and "Direct3DCreate8" in e.fatal:
        print("Direct3DCreate8 argument (D3D_SDK_VERSION) = %d" % e.fatal_args[0])
    print("MFC calls (lenient):")
    for (n, frm), c in sorted(e.mfc_calls.items(), key=lambda kv: -kv[1])[:30]:
        print("  %-8s x%-3d from %s" % (n, c, frm))
    if e.pc_trace:
        print("last executed instructions:")
        for a in list(e.pc_trace)[-25:]:
            print("   ", e.module_at(a))
    print("file-system activity during InitInstance:")
    for l in e.apilog:
        if any(k in l for k in ("FindFirst", "FindNext", "CreateFile", "GetFileAttr", "SetCurrentDir", "GetCurrentDir", "GetFullPath")):
            print("  ", l[:170])
    print("SEH trace:")
    for l in e.apilog:
        if l.startswith("SEH") or "RtlUnwind" in l:
            print("  ", l[:420])
    print("windows created (CreateWindowEx):")
    for l in getattr(e, "win_log", []):
        print("  ", l[:200])
    print("window/dialog calls during InitInstance (USER32/GDI32, last 40):")
    _w = [l for l in e.apilog if l.startswith(("USER32", "GDI32")) and not any(k in l for k in ("GetDC", "ReleaseDC", "GetSystemMetrics"))]
    for l in _w[-40:]:
        print("  ", l[:150])
    print("INI accesses during InitInstance:")
    for l in getattr(e, "ini_log", []):
        print("  ", l[:170])
    print("registry accesses during InitInstance:")
    for l in getattr(e, "reg_log", []):
        print("  ", l[:170])
    print("host (HLE) calls: %d total; top:" % sum(e.stub_counts.values()))
    for (d, n), c in e.stub_counts.most_common(14):
        print("   %8d  %s!%s" % (c, d, n))
    print("last API calls:")
    for l in list(e.apilog)[-14:]:
        print("  ", l)

    if hasattr(e, "d3d"):
        out = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "census", "d3d8_usage.md")
        open(out, "w").write(e.d3d.report())
        print("Direct3D 8 usage report written to census/d3d8_usage.md (%d distinct methods, %d draw calls, %d frames)" % (
            len(e.d3d.calls), sum(e.d3d.draws.values()), getattr(e.d3d, "frames", 0)))

    if hasattr(e, "dshow"):
        out = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "census", "dshow_usage.md")
        open(out, "w").write(e.dshow.report())
        print("DirectShow usage report written to census/dshow_usage.md:")
        for l in e.dshow.events:
            print("  ", l)

    if hasattr(e, "ds"):
        out = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "census", "dsound_usage.md")
        open(out, "w").write(e.ds.report())
        print("DirectSound usage report written to census/dsound_usage.md (%d distinct methods, %d buffers)" % (
            len(e.ds.calls), len(e.ds.buffers)))

    if hasattr(e, "di"):
        out = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "census", "dinput_usage.md")
        open(out, "w").write(e.di.report())
        print("DirectInput usage report written to census/dinput_usage.md (%d distinct methods, %d devices)" % (
            len(e.di.calls), len(e.dinput.devices)))


if not REAL:
    r = e.call(0x40b7a0, ecx=app, max_insns=CAP, timeout=0 if CAP else TIMEOUT)     # slot 22 = InitInstance
    if e.budget_exhausted:
        e.fatal = "InitInstance did not finish within %s" % ("--cap %d instructions" % CAP if CAP else "--timeout %gs" % TIMEOUT)
        r = 0
    init_report(r)

# ------------------------------------------------------------ main loop: CMaxPayneApp::Run is `while (frame()) {}`
# with frame = maxpayne.exe+0x40c020 (engine update + render, then a PeekMessage/Dispatch pump; FALSE on WM_QUIT).
# --frames N calls it N times. --input "F:ACTION,..." injects host input before frame F, where ACTION is
# key=DIK (hex) / keyup=DIK / move=dx;dy / wheel=dz / button=n / buttonup=n / focus=0|1. Example: --input "40:key=1,41:keyup=1".
FRAME = 0x40c020
# --window: show the game live through the Metal renderer (emu/live.py) and play it with keyboard and mouse;
# runs until the window is closed (or --frames N).
# --real-entry: the game runs from its entry point (the CRT, WinMain, AfxWinMain, InitInstance, CMaxPayneApp::Run)
# and the per-frame work below runs each time the frame function is entered: through the lifted library's entry hook
# (build.py --entry-hook 0x40c020) or, under the emulator, a code hook. The run ends the way the game ends: the
# harness posts WM_QUIT (window closed, --frames reached, a stop condition) and ExitInstance and the CRT exit run.
if REAL or (('--frames' in sys.argv or '--window' in sys.argv) and r and not e.fatal):
    nframes = int(sys.argv[sys.argv.index('--frames') + 1]) if '--frames' in sys.argv else 10 ** 9
    live = None
    # Frame numbers written "@N" count from an anchor instead: the frame in which the game first opens a file whose
    # name contains --anchor TEXT (case-insensitive), e.g. --anchor P1L0a_001.kf2 --input "@20:key=1c,@21:keyup=1c".
    anchor = sys.argv[sys.argv.index('--anchor') + 1].lower() if '--anchor' in sys.argv else None
    anchor_frame = None
    script, anchored = {}, {}
    if '--input' in sys.argv:
        for item in sys.argv[sys.argv.index('--input') + 1].split(","):
            f, act = item.split(":", 1)
            (anchored if f.startswith("@") else script).setdefault(int(f.lstrip("@")), []).append(act)

    def apply(act):
        k, _, v = act.partition("=")
        di = e.dinput
        if k == "key": di.key(int(v, 16), True)
        elif k == "keyup": di.key(int(v, 16), False)
        elif k == "move": di.mouse_move(*map(int, v.split(";")))
        elif k == "wheel": di.mouse_wheel(int(v))
        elif k == "button": di.mouse_button(int(v), True)
        elif k == "buttonup": di.mouse_button(int(v), False)
        elif k == "focus": __import__("winsys").host_set_app_active(e, v == "1")
        else: raise SystemExit("bad --input action %r" % act)
    if '--fpu-watch' in sys.argv:
        # log every fldcw that loads a control word other than 53-bit precision / round-to-nearest
        import capstone
        from unicorn import UC_HOOK_CODE
        from capstone.x86 import X86_OP_MEM
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        regs = {n: getattr(__import__("unicorn.x86_const", fromlist=["x"]), "UC_X86_REG_" + n.upper())
                for n in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")}
        fpu_log = []
        fpu_last = [None]
        nsites = 0
        for mod in e.modules.values():
            for sec in mod.pe.sections:
                if not sec.Characteristics & 0x20000000:
                    continue
                lo = mod.base + sec.VirtualAddress
                code = e.rd(lo, max(sec.Misc_VirtualSize, sec.SizeOfRawData))
                for ins in md.disasm(code, lo):
                    if ins.mnemonic in ("fninit", "finit", "fldenv", "frstor", "fxrstor", "fnrstor"):
                        def _oh(uc, address, size, user, _m=ins.mnemonic):
                            fpu_last[0] = "%s at %s" % (_m, e.module_at(address))
                        e.uc.hook_add(UC_HOOK_CODE, _oh, begin=ins.address, end=ins.address)
                        nsites += 1
                        continue
                    if ins.mnemonic != "fldcw":
                        continue
                    op = ins.operands[0]
                    if op.type != X86_OP_MEM:
                        continue
                    base = ins.reg_name(op.mem.base) if op.mem.base else None
                    idx = ins.reg_name(op.mem.index) if op.mem.index else None
                    def _fh(uc, address, size, user, _b=base, _i=idx, _sc=op.mem.scale, _d=op.mem.disp):
                        a = (_d + (uc.reg_read(regs[_b]) if _b else 0) + (uc.reg_read(regs[_i]) * _sc if _i else 0)) & 0xFFFFFFFF
                        cw = struct.unpack("<H", bytes(uc.mem_read(a, 2)))[0]
                        fpu_last[0] = "fldcw 0x%04x at %s" % (cw, e.module_at(address))
                        if cw & 0xF00 != 0x200:
                            fpu_log.append("fldcw 0x%04x at %s (return address on stack: %s)" % (
                                cw, e.module_at(address), e.module_at(e.rd32(uc.reg_read(UC_X86_REG_ESP)))))
                    e.uc.hook_add(UC_HOOK_CODE, _fh, begin=ins.address, end=ins.address)
                    nsites += 1
        e.uc.ctl_flush_tb()         # hooks only reach code translated after they are added
        print("fpu-watch: hooked %d fldcw sites" % nsites)
    if '--precision-callers' in sys.argv:
        # one hook on rlmfc's M_FPUControl::setPrecision: who changes the x87 precision, and to what
        from unicorn import UC_HOOK_CODE
        sp_va = e.modules["rlmfc.dll"].exports["?setPrecision@M_FPUControl@@QAEXW4Precision@1@@Z"]
        prec_calls = []
        rl = e.modules["rlmfc.dll"]

        def _ph(uc, address, size, user):
            sp = uc.reg_read(UC_X86_REG_ESP)
            ret = e.rd32(sp)
            if rl.base <= ret < rl.base + rl.size:       # called by an M_FPUControl constructor: logged there
                return
            prec_calls.append((e.rd32(sp + 4), e.module_at(ret)))
        e.uc.hook_add(UC_HOOK_CODE, _ph, begin=sp_va, end=sp_va)
        for ctor, argi in (("??0M_FPUControl@@QAE@W4Precision@0@@Z", 1), ("??0M_FPUControl@@QAE@W4Rounding@0@W4Precision@0@@Z", 2)):
            va = rl.exports.get(ctor)
            if va is None:
                print("precision-callers: no export", ctor)
                continue
            def _ch(uc, address, size, user, _i=argi):
                sp = uc.reg_read(UC_X86_REG_ESP)
                prec_calls.append((e.rd32(sp + 4 * _i), "M_FPUControl ctor from " + e.module_at(e.rd32(sp))))
            e.uc.hook_add(UC_HOOK_CODE, _ch, begin=va, end=va)
        e.uc.ctl_flush_tb()
    SLICE = float(sys.argv[sys.argv.index('--frame-slice') + 1]) if '--frame-slice' in sys.argv else 60
    e.apilog = mpemu.ApiLog(maxlen=2_000_000)            # keep a whole frame's log (loading frames are long)
    # --capture DIR --capture-frames 5,40: write those frames as MPD3 command streams (emu/d3dcap.py)
    cap_spec = sys.argv[sys.argv.index('--capture-frames') + 1].split(",") if '--capture-frames' in sys.argv else []
    cap_frames = set(int(x) for x in cap_spec if not x.startswith("@"))
    cap_anchored = set(int(x[1:]) for x in cap_spec if x.startswith("@"))
    cap_dir = sys.argv[sys.argv.index('--capture') + 1] if '--capture' in sys.argv else "captures"
    if cap_spec:
        os.makedirs(cap_dir, exist_ok=True)
    # --dump-api 1320,1400: print every HLE call made during those frames
    dump_spec = sys.argv[sys.argv.index('--dump-api') + 1].split(",") if '--dump-api' in sys.argv else []
    dump_frames = set(int(x) for x in dump_spec if not x.startswith("@"))
    dump_anchored = set(int(x[1:]) for x in dump_spec if x.startswith("@"))
    # --smc-scan F: during frame F record which 4 KB pages hold executed code; during frame F+1 count guest writes
    # into those pages (each one sends Unicorn/QEMU down its self-modifying-code path) and report who writes.
    smc = {"pages": set(), "hooks": [], "writes": collections.Counter(), "writers": collections.Counter()}

    def smc_scan(step):
        from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE
        for h in smc["hooks"]:
            e.uc.hook_del(h)
        smc["hooks"] = []
        if step == 0:
            def _blk(uc, address, size, user):
                smc["pages"].update(range(address >> 12, ((address + size - 1) >> 12) + 1))
            smc["hooks"].append(e.uc.hook_add(UC_HOOK_BLOCK, _blk))
            e.uc.ctl_flush_tb()     # hooks only reach code translated after they are added
            return
        def _wr(uc, access, address, size, value, user):
            if address >> 12 in smc["pages"]:
                smc["writes"][address >> 12] += 1
                smc["writers"][uc.reg_read(UC_X86_REG_EIP)] += 1
        smc["hooks"].append(e.uc.hook_add(UC_HOOK_MEM_WRITE, _wr))
        e.uc.ctl_flush_tb()

    def smc_report():
        print("smc-scan: %d code pages executed; writes into them during one frame: %d" % (
            len(smc["pages"]), sum(smc["writes"].values())))
        for pg, n in smc["writes"].most_common(15):
            print("   %8d writes to page 0x%08x (%s)" % (n, pg << 12, e.module_at(pg << 12)))
        for va, n in smc["writers"].most_common(15):
            print("   %8d writes by %s" % (n, e.module_at(va)))

    def start_loop():
        """The live view's renderer and the counters at the start of the main loop."""
        global live, _fs0, _gc0, _ec0, _crt0, _hd0, _hh0, _cc0, _hf0, _hp0, prof_from, prof, t0
        if '--window' in sys.argv:
            live = e.live
            live.attach_renderer()
            print("live view open: the game captures the mouse; Cmd+Esc releases it (click to return), Cmd+Return toggles fullscreen, close the window to stop")
        print("running %d frames of the main loop" % nframes)
        _fs0 = native.fast_stats() if native is not None and native._fast else None     # fast counters at loop start
        _gc0 = native.fast_guest_counts() if _fs0 is not None else None
        _ec0 = native.fast_entry_callers() if _fs0 is not None else None
        _crt0 = native.crt_counts() if _fs0 is not None else None
        _hd0 = native.hle_direct_calls if _fs0 is not None else 0
        _hh0 = native.heap_direct_calls if _fs0 is not None else (0, 0)
        _cc0 = native.call_cache_stats if native is not None else (0, 0)
        _hf0 = native.hle_fast_calls if native is not None else 0
        _hp0 = (e.hle_direct_n.copy(), e.hle_direct_ns.copy(), e.hle_direct_total_ns)   # direct-call profile at loop start
        # --profile F: profile the host (Python) side from frame F on; time not attributed to a Python function is
        # spent inside Unicorn (emu_start's own time).
        prof_from = int(sys.argv[sys.argv.index('--profile') + 1]) if '--profile' in sys.argv else None
        prof = None
        t0 = time.time()

    def quit_requested(i):
        if live:
            live.pump()
            if live.quit:
                print("window closed after %d frames" % i)
                return True
        return False

    def before_frame(i):
        global prof, capturing, draws0, frames0, polls0, calls0, t, seh_head
        acts = script.get(i, []) + (anchored.get(i - anchor_frame, []) if anchor_frame is not None else [])
        for act in acts:
            apply(act)
            print("  input before frame %d: %s" % (i, act))
        if i == prof_from:
            import cProfile
            prof = cProfile.Profile()
            prof.enable()
        if '--smc-scan' in sys.argv and i in (int(sys.argv[sys.argv.index('--smc-scan') + 1]),
                                               int(sys.argv[sys.argv.index('--smc-scan') + 1]) + 1):
            smc_scan(i - int(sys.argv[sys.argv.index('--smc-scan') + 1]))
        capturing = (i in cap_frames or (anchor_frame is not None and i - anchor_frame in cap_anchored)) and not live
        if capturing:
            __import__("d3d8").start_capture(e, os.path.join(cap_dir, "frame_%03d.mpd3" % i))
        draws0, frames0, polls0 = sum(e.d3d.draws.values()), getattr(e.d3d, "frames", 0), sum(e.di.polls.values())
        calls0 = sum(e.stub_counts.values())
        t = time.time()
        e.apilog.clear()
        seh_head = e.rd32(mpemu.TEB)

    def after_frame(i, cont, slices):
        """The frame's report, probes and stop conditions. True: stop the run."""
        global anchor_frame
        if slices > 1:
            print("  (long frame: %d slices of %gs)" % (slices, SLICE))
        print("frame %3d: %s  %.1fs  host calls %6d  draws %3d  presents %d  input polls %d" % (
            i, "continue" if cont else "QUIT", time.time() - t, sum(e.stub_counts.values()) - calls0,
            sum(e.d3d.draws.values()) - draws0, getattr(e.d3d, "frames", 0) - frames0,
            sum(e.di.polls.values()) - polls0))
        if capturing:
            c = __import__("d3d8").stop_capture(e)
            print("  captured -> %s (%s)" % (c.f.name, ", ".join("%s %d" % (__import__("d3dcap").NAMES[k], v) for k, v in sorted(c.counts.items()))))
        if i in dump_frames or (anchor_frame is not None and i - anchor_frame in dump_anchored):
            for l in e.apilog:
                print("    api:", l[:300])
        opened = [l.split("[", 1)[1].rstrip("]") for l in e.apilog if "CreateFileA" in l and "[" in l]
        if anchor and anchor_frame is None and any(anchor in o.lower() for o in opened):
            anchor_frame = i
            print("  anchor %r opened in frame %d" % (anchor, i))
        # --probe FILE: a Python file run after every frame with e, i (frame) and anchor_frame in scope
        if '--probe' in sys.argv:
            exec(open(sys.argv[sys.argv.index('--probe') + 1]).read(), {"e": e, "i": i, "anchor_frame": anchor_frame, "mpemu": mpemu})
        if anchor_frame is not None and '--anchor-frames' in sys.argv and i - anchor_frame >= int(sys.argv[sys.argv.index('--anchor-frames') + 1]):
            print("  stopping %d frames after the anchor" % (i - anchor_frame))
            return True
        if opened:
            print("  files opened: %d, e.g. %s" % (len(opened), ", ".join(opened[:4])))
        if e.rd32(mpemu.TEB) != seh_head and not e.fatal:
            chain, f = [], e.rd32(mpemu.TEB)
            while f not in (0xFFFFFFFF, 0) and len(chain) < 8:
                chain.append("0x%x[%s]" % (f, e.module_at(e.rd32(f + 4))))
                f = e.rd32(f)
            print("  SEH chain head changed during the frame: 0x%x -> 0x%x; chain now %s" % (seh_head, e.rd32(mpemu.TEB), " -> ".join(chain)))
            seh = [l for l in e.apilog if l.startswith("SEH") or "RtlUnwind" in l or "ExceptionNested" in l]
            print("  SEH events this frame: %d" % len(seh))
            for l in seh[:60]:
                print("     ", l[:300])
        if '--fpu-watch' in sys.argv and fpu_log:
            print("  non-default FPU control words loaded: %d" % len(fpu_log))
            for l in collections.Counter(fpu_log).most_common(12):
                print("     %4dx %s" % (l[1], l[0]))
            fpu_log.clear()
        if '--precision-callers' in sys.argv:
            from unicorn.x86_const import UC_X86_REG_FPCW
            names = {0: "24-bit", 0x200: "53-bit", 0x300: "64-bit"}
            print("  setPrecision calls: %d; FPU control word at frame end 0x%04x; last calls: %s" % (
                len(prec_calls), e.uc.reg_read(UC_X86_REG_FPCW),
                "; ".join("%s from %s" % (names.get(a, hex(a)), c) for a, c in prec_calls[-4:])))
            if len(prec_calls) > 1:
                print("  callers this frame:", dict(collections.Counter("%s %s" % (names.get(a, hex(a)), c) for a, c in prec_calls).most_common(8)))
            prec_calls.clear()
        if '--fpu-watch' in sys.argv:
            from unicorn.x86_const import UC_X86_REG_FPCW
            print("  FPU control word at frame end: 0x%04x; last control-word change: %s" % (
                e.uc.reg_read(UC_X86_REG_FPCW), fpu_last[0]))
        if e.fatal:
            print("  stopped:", e.fatal)
            print("  at:", e.where(), "->", e.module_at(e.uc.reg_read(UC_X86_REG_EIP)))
            for l in list(e.apilog)[-12:]:
                print("    ", l[:170])
            return True
        if not cont:
            return True
        return False

    if not REAL:
        start_loop()
        for i in range(nframes):
            if quit_requested(i):
                break
            before_frame(i)
            cont = e.call(FRAME, ecx=app, timeout=SLICE) & 0xFF
            slices = 1
            while e.budget_exhausted:                       # a long frame (level load): keep going, same frame
                slices += 1
                cont = e.resume(timeout=SLICE) & 0xFF
            if after_frame(i, cont, slices):
                break
    else:
        real = {"i": -1, "quit": False}           # the frame being run; WM_QUIT posted

        def _quit():
            if not real["quit"]:
                real["quit"] = True
                __import__("winsys").host_post_quit(e)

        def on_frame(va):
            # the frame that sees WM_QUIT still runs (update and render, then its pump returns FALSE): it is the last
            if real["i"] < 0:
                init_report(1)
                start_loop()
            elif after_frame(real["i"], 1, 1):
                _quit()
            real["i"] += 1
            if quit_requested(real["i"]) or real["i"] >= nframes - 1:
                _quit()
            before_frame(real["i"])
        if native is not None:
            # the library may hook other functions too (H75: the HUD's, for mphost): only the frame function counts
            if not native.set_entry_hook(lambda va: on_frame(va) if va == FRAME else None):
                raise SystemExit("--real-entry needs a library built with --entry-hook 0x%x (H63 or later)" % FRAME)
        else:
            from unicorn import UC_HOOK_CODE
            e.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: on_frame(a), begin=FRAME, end=FRAME)
        try:
            e.call(exe.entry)
        except RuntimeError:                       # native.NativeError: the exit ended the native frames
            if e.exit_code is None or e.fatal:
                raise
        if native is not None:
            native.set_entry_hook(None)
        print("process exit code %s after %d frames: %s" % (e.exit_code, real["i"] + 1, e.fatal or "no fault"))
        if real["i"] < 0:
            init_report(0)
        else:
            after_frame(real["i"], 0, 1)
    print("main loop: %.1fs" % (time.time() - t0))
    if _fs0 is not None:      # the fast counters of the main loop alone (the stats line below covers InitInstance too)
        _fs1 = native.fast_stats()
        print("main loop, fast path: " + ", ".join("%s %d" % (k, _fs1[k] - _fs0[k]) if k not in ("max_depth",)
                                                  else "max_depth %d" % _fs1[k] for k in _fs1)
              + "; native %.2fs, guest runs %.2fs (exclusive times: together, the time inside native calls)" % (
                  (_fs1["native_ns"] - _fs0["native_ns"]) / 1e9, (_fs1["guest_ns"] - _fs0["guest_ns"]) / 1e9))
        # the guest functions native code called most in the main loop (module!export where the target is an export)
        _exp = {va: "%s!%s" % (m.name, n) for m in e.modules.values() for n, va in m.exports.items()}
        # HLE stubs (Python handlers at STUB_BASE): "stub dll!name"
        _exp.update({mpemu.STUB_BASE + i * mpemu.STUB_STRIDE: "stub %s!%s" % k for i, k in enumerate(e.stubs)})
        _gc = native.fast_guest_counts()
        _top = sorted(((n - _gc0.get(a, 0), a) for a, n in _gc.items()), reverse=True)[:int(
            sys.argv[sys.argv.index('--guest-top') + 1]) if '--guest-top' in sys.argv else 15]
        _crt1 = native.crt_counts()
        print("main loop, native CRT helpers: " + (", ".join("%s %d" % (k, _crt1[k] - _crt0.get(k, 0)) for k in _crt1)
                                                   or "none bound"))
        print("main loop, direct HLE calls (no emulator): %d" % (native.hle_direct_calls - _hd0))
        _hh = native.heap_direct_calls
        print("main loop, heap calls served in C: HeapAlloc %d, HeapFree %d" % (_hh[0] - _hh0[0], _hh[1] - _hh0[1]))
        _cc = native.call_cache_stats
        print("main loop, call-target cache: %d hits, %d misses" % (_cc[0] - _cc0[0], _cc[1] - _cc0[1]))
        print("main loop, HLE calls served in C (QPC, D3D8): %d" % (native.hle_fast_calls - _hf0))
        # where the direct calls' time goes: handler time by handler (--hle-top N, default 20), and Emu.hle_direct
        # as a whole; the rest of the guest bucket's share is the ctypes callback and runtime.c
        _hp = e.hle_direct_profile(int(sys.argv[sys.argv.index('--hle-top') + 1]) if '--hle-top' in sys.argv else 20,
                                   since=_hp0[:2])
        _hn = sum((e.hle_direct_n - _hp0[0]).values())
        _hns = sum((e.hle_direct_ns - _hp0[1]).values())
        print("main loop, direct HLE handlers: %d calls, handlers %.2fs, Emu.hle_direct %.2fs; top by handler time:" % (
            _hn, _hns / 1e9, (e.hle_direct_total_ns - _hp0[2]) / 1e9))
        for (_d, _nm), _c, _ns in _hp:
            print("  %10d  %8.1f ms  %6.2f us/call  %s!%s" % (_c, _ns / 1e6, _ns / 1e3 / _c, _d, _nm))
        print("main loop, guest calls from native code by target:")
        for _n, _a in _top:
            if _n:
                print("  %10d  %08x  %s" % (_n, _a, _exp.get(_a) or e.module_at(_a)))
        # the main loop's fast-path entries by caller. The containing function is the inventory entry (any module)
        # whose range holds the return address; the exe has no inventory, so its callers stay module+offset.
        _ec = {a: n - _ec0.get(a, 0) for a, n in native.fast_entry_callers().items()}
        _ec = sorted(((n, a) for a, n in _ec.items() if n > 0), reverse=True)
        # the exe's inventory names its callers even when the exe is not in the library (--lift-modules without it)
        _caller_invs = list(_invs) + [p for p in [os.path.join(_root, "lift-out", "maxpayne_functions.json")]
                                      if "maxpayne.exe" not in _mods and os.path.exists(p)]
        _starts = sorted((int(f["entry"], 16), int(f["size"])) for _inv in _caller_invs
                         for f in json.load(open(_inv))["functions"])
        _keys = [s for s, _ in _starts]

        def _fn_of(ra):
            i = bisect.bisect_right(_keys, ra) - 1
            return _starts[i][0] if i >= 0 and ra < _starts[i][0] + _starts[i][1] else None
        _by_mod = collections.Counter()
        for _n, _a in _ec:
            _by_mod[e.module_at(_a).split("+")[0]] += _n
        print("main loop, fast-path entries by module (total %d):" % sum(n for n, _ in _ec))
        for _m, _n in _by_mod.most_common():
            print("  %10d  %s" % (_n, _m))
        _k = int(sys.argv[sys.argv.index('--caller-top') + 1]) if '--caller-top' in sys.argv else 25
        print("main loop, fast-path entries by caller (top %d):" % _k)
        for _n, _a in _ec[:_k]:
            _f = _fn_of(_a)
            print("  %10d  %s  function %s" % (_n, e.module_at(_a), "%08x" % _f if _f is not None else "unknown"))
    if smc["pages"]:
        for h in smc["hooks"]:
            e.uc.hook_del(h)
        smc_report()
    if prof:
        import pstats
        prof.disable()
        print("host profile from frame %d (tottime = time in that function itself):" % prof_from)
        pstats.Stats(prof).sort_stats("tottime").print_stats(25)
    if live:
        print("live view: %d frames presented" % live.frames)
        print("live view, present: " + live.timing())
    if live and live.notes():
        print("renderer notes:\n  " + live.notes().replace("\n", "\n  "))
    out = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "census", "dinput_usage.md")
    open(out, "w").write(e.di.report())
    open(out.replace("dinput", "d3d8"), "w").write(e.d3d.report())
    open(out.replace("dinput", "dsound"), "w").write(e.ds.report())
    if getattr(e, "_ds_mixer", None):
        mx = e._ds_mixer
        print("audio: %.1fs mixed%s" % (mx.lib.mpa_frames_out(mx.m) / 44100, " -> " + e.audio_record if e.audio_record else ""))
        mx.close()

if rec_hits is not None:
    _txt = next(s for s in exe.pe.sections if s.Name.startswith(b".text"))
    _tlo, _thi = exe.base + _txt.VirtualAddress, exe.base + _txt.VirtualAddress + _txt.Misc_VirtualSize
    _calls, _jmps, _samp = collections.Counter(), collections.Counter(), collections.defaultdict(list)
    for (_site, _t), _n in rec_hits.items():               # first-execution order: the first callers seen
        if not _tlo <= _t < _thi:
            continue
        if rec_sites[_site][0]:
            _calls[_t] += _n
            if len(_samp[_t]) < 3 and _site not in _samp[_t]:
                _samp[_t].append(_site)
        else:
            _jmps[_t] += _n
    _out = sys.argv[sys.argv.index('--record-entries') + 1]
    with open(_out, "w") as _fh:
        json.dump({"calls": {"0x%08x" % _t: _n for _t, _n in sorted(_calls.items())},
                   "indirect_jmps": {"0x%08x" % _t: _n for _t, _n in sorted(_jmps.items())},
                   "callers_sample": {"0x%08x" % _t: ["0x%08x" % _s for _s in _samp[_t]] for _t in sorted(_calls)}},
                  _fh, indent=1)
    print("record-entries: %d distinct exe call targets (%d calls), %d distinct indirect-jmp targets (%d jmps) -> %s" % (
        len(_calls), sum(_calls.values()), len(_jmps), sum(_jmps.values()), _out))
    print("record-entries: self-check: direct calls whose block did not start at the operand target: %d; indirect jmps dropped (target != operand value): %d" % (
        rec_mismatch[0], rec_jmp_drop[0]))
    for _t, _n in _calls.most_common(20):
        print("   %9d  0x%08x  %s" % (_n, _t, e.module_at(_t)))

if guest_blocks is not None:
    print("guest-blocks: %d blocks executed by the emulator in module images (%d distinct), patched entries aside%s" % (
        sum(guest_blocks.values()), len(guest_blocks), ":" if guest_blocks else ""))
    for _a, _n in guest_blocks.most_common(20):
        print("   %9d  %s" % (_n, e.module_at(_a)))

if native is not None:
    if _loader is not None:
        _loader.finish()                                    # "[lift] <module>: never loaded" for deferred modules
        print("lifted functions installed or hooked in all: %d" % _loader.count)
    print("native calls: %d %s" % (native.calls, native.stats()))
    if native._fast and '--native-counts' in sys.argv:          # per-function call counts of the fast path (JSON)
        import json
        _counts = {"0x%08x" % va: n for va, n in native.fast_call_counts().items()}
        with open(sys.argv[sys.argv.index('--native-counts') + 1], "w") as _fh:
            json.dump({"stats": native.fast_stats(), "calls": _counts}, _fh, indent=1)
    if native.diffing:
        for _l in native.summary_lines():
            print(_l)
        if '--diff-report' in sys.argv:
            import json
            _path = sys.argv[sys.argv.index('--diff-report') + 1]
            with open(_path, "w") as _fh:
                json.dump(native.report(), _fh, indent=1)
            print("diff report written to %s" % _path)
