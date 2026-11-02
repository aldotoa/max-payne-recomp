# Summarise an MPR_FRAME_LOG file (render/mprender.h): per-frame CPU work, nextDrawable wait, GPU time, on-screen
# intervals and latency. Usage: frame_log.py LOG [FIRST_FRAME]   (frames over 100 ms of CPU, level loads, are left out)
import sys, statistics as st
F, G, P = {}, {}, {}
for l in open(sys.argv[1]):
    t = l.split()
    if not t or t[0] == "#": continue
    i = int(t[1])
    if t[0] == "F": F[i] = tuple(map(float, t[2:]))
    elif t[0] == "G": G[i] = (float(t[2]), float(t[3]))
    elif t[0] == "P": P[i] = float(t[2])
skip = int(sys.argv[2]) if len(sys.argv) > 2 else 0
idx = sorted(i for i in F if i >= skip)
# steady part: drop frames with huge cpu (level load)
idx = [i for i in idx if F[i][1] < 100]
def q(v, p): v = sorted(v); return v[min(len(v) - 1, int(len(v) * p))]
def show(name, v):
    print("%-22s n=%5d mean %6.2f  p10 %6.2f  p50 %6.2f  p90 %6.2f  p99 %6.2f" % (name, len(v), st.mean(v), q(v,.1), q(v,.5), q(v,.9), q(v,.99)))
cpu = [F[i][1] for i in idx]; wait = [F[i][2] for i in idx]
iv = [F[i][0] - F[i-1][0] for i in idx if i-1 in F]
show("frame interval", iv); show("cpu work", cpu); show("nextDrawable wait", wait)
show("gpu time", [G[i][1]-G[i][0] for i in idx if i in G])
pres = [i for i in idx if P.get(i, 0) > 0]
print("presented %d of %d (never shown %d)" % (len(pres), len(idx), sum(1 for i in idx if P.get(i, -1) == 0)))
pi = [P[b] - P[a] for a, b in zip(pres, pres[1:]) if b == a + 1]
if pi: show("on-screen interval", pi)
show("submit->screen", [P[i] - F[i][0] for i in pres])
print("cpu>16.7: %.1f%%  cpu>15: %.1f%%" % (100*sum(c>16.7 for c in cpu)/len(cpu), 100*sum(c>15 for c in cpu)/len(cpu)))
# wait vs previous cpu correlation
import itertools
print("wait when cpu<12: %.2f, cpu 12-16: %.2f, cpu>16: %.2f" % tuple(
    st.mean([F[i][2] for i in idx if lo <= F[i][1] < hi] or [0]) for lo, hi in ((0,12),(12,16),(16,999))))
# on-screen intervals histogram in vsync multiples
if pi:
    import collections
    h = collections.Counter(round(x / 16.667) for x in pi); print("on-screen interval in vsyncs:", sorted(h.items()))
