#!/usr/bin/env python3
"""rand() calls per frame from an MPH_RAND_LOG file (mphost, M7): MSVCRT's rand is the LCG x' = x * 214013 + 2531011
(mod 2^32), so the calls between two logged states are the steps from one to the other.

Usage: rand_steps.py LOG FPS [FIRST_FRAME [WINDOW_S]]   prints rand() calls per sim second, per window
"""
import sys

A, C, M = 214013, 2531011, 1 << 32
LIMIT = 200000


def steps(a, b):
    x = a
    for k in range(LIMIT):
        if x == b:
            return k
        x = (x * A + C) % M
    return None


def main():
    log, fps = sys.argv[1], int(sys.argv[2])
    first = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    win = float(sys.argv[4]) if len(sys.argv) > 4 else 1.0
    rows = [tuple(map(int, l.split())) for l in open(log)]
    rows = [r for r in rows if r[0] >= first]
    per = int(round(win * fps))
    total = 0
    for i in range(0, len(rows) - per, per):
        n = 0
        for (fa, a), (fb, b) in zip(rows[i:i + per], rows[i + 1:i + per + 1]):
            k = steps(a, b)
            if k is None:
                sys.exit("frame %d: more than %d calls" % (fb, LIMIT))
            n += k
        total += n
        print("t %6.2f s  rand/s %8.1f" % ((rows[i][0] - first) / fps, n / win))
    print("mean rand/s %.1f" % (total / ((len(rows) - 1) // per * win)))


if __name__ == "__main__":
    main()
