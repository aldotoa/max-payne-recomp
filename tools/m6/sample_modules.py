"""Group one thread of a macOS `sample` call tree by guest module and by cost kind (H53).
Self samples of lifted functions (f_XXXXXXXX) go to the module whose inventory (lift-out/*_functions.json) holds the
address; the rest go by library. Also prints inclusive samples for the guest functions given with --incl.
Usage: sample_modules.py FILE START END [--incl 0x601250,0x6014d0]"""
import collections, glob, json, re, sys
f, a, b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
incl_vas = [int(x, 16) for x in sys.argv[sys.argv.index("--incl") + 1].split(",")] if "--incl" in sys.argv else []
ranges = []
for p in glob.glob("lift-out/*_functions.json"):
    d = json.load(open(p))
    lo = int(d["base"], 16)
    hi = max(int(fn["blocks"][-1]["end"], 16) if fn.get("blocks") else int(fn["entry"], 16) + fn.get("size", 1) for fn in d["functions"])
    ranges.append((lo, hi, d["module"]))
def module(va):
    for lo, hi, m in ranges:
        if lo <= va < hi:
            return m
    return "lifted ?"
pat = re.compile(r"^(\s*[+!:| ]*)(\d+) (.+?)  \(in ([^)]+)\)")
lines = open(f).read().split("\n")[a - 1:b - 1]
stack, selfc, inclc, total = [], collections.Counter(), collections.Counter(), None
def kind(sym, lib):
    m = re.match(r"f_([0-9a-f]{8})$", sym)
    if m:
        return "lifted " + module(int(m.group(1), 16))
    if sym in ("semaphore_timedwait_trap", "semaphore_wait_trap"):
        return "wait (nextDrawable / vsync)"
    if "liblifted" in lib:
        return "lift runtime (" + ("x87" if sym.startswith("x87") else sym if sym in ("lift_call_ret", "lift_call", "lift_jump") else "other") + ")"
    if lib == "Python" or lib.startswith("_") and "cpython" in lib:
        return "Python"
    if lib.startswith("libunicorn"):
        return "emulator (Unicorn)"
    return "other: " + lib
def pop():
    d, c, key, kids = stack.pop()
    selfc[kind(*key)] += c - kids
for l in lines:
    m = pat.match(l)
    if not m:
        continue
    d, c = len(m.group(1)), int(m.group(2))
    key = (m.group(3).split(" + ")[0], m.group(4))
    if total is None:
        total = c
    while stack and stack[-1][0] >= d:
        pop()
    if stack:
        stack[-1][3] += c
    for va in incl_vas:   # count the outermost occurrence only
        if key[0] == "f_%08x" % va and not any(s[2][0] == key[0] for s in stack):
            inclc[va] += c
    stack.append([d, c, key, 0])
while stack:
    pop()
wait = selfc["wait (nextDrawable / vsync)"]
print("thread samples %d, of them waiting %d; busy %d" % (total, wait, total - wait))
for k, c in selfc.most_common():
    if c >= total * 0.002:
        print("%7d %5.1f%% of busy  %s" % (c, 100 * c / max(total - wait, 1) if not k.startswith("wait") else 0, k))
for va in incl_vas:
    print("inclusive f_%08x: %d (%.1f%% of busy)" % (va, inclc[va], 100 * inclc[va] / max(total - wait, 1)))
