"""Self and inclusive samples per symbol in one thread of a macOS `sample` call tree (H46).
The thread is the line range START..END of the file (a thread header line and the next one).
Usage: sample_selftime.py FILE START END [TOP]"""
import re, sys, collections
f, a, b = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
top = int(sys.argv[4]) if len(sys.argv) > 4 else 60
lines = open(f).read().split("\n")[a - 1:b - 1]
pat = re.compile(r"^(\s*[+!:| ]*)(\d+) (.+?)  \(in ([^)]+)\)")
selfc = collections.Counter(); libc = collections.Counter(); incl = collections.Counter()
stack = []          # [depth, count, key, childsum]
total = None

def pop():
    d, c, key, kids, path = stack.pop()
    sc = c - kids
    selfc[key] += sc
    libc[key[1]] += sc
    if key not in path:
        incl[key] += c

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
    path = frozenset(s[2] for s in stack)
    if stack:
        stack[-1][3] += c
    stack.append([d, c, key, 0, path])
while stack:
    pop()
print("thread samples", total)
print("-- self by library")
for lib, c in libc.most_common(12):
    print("%7d %5.1f%%  %s" % (c, 100 * c / total, lib))
print("-- self by symbol")
for (s, lib), c in selfc.most_common(top):
    print("%7d %5.1f%%  %s  [%s]   incl %d" % (c, 100 * c / total, s, lib, incl[(s, lib)]))
