#!/usr/bin/env python3
"""Compare two PNGs (RGB): mean absolute error and the share of pixels that differ by more than a tolerance.
Writes an amplified difference image when -o is given. Exit status 1 if the images differ beyond --max-bad.

Usage: imgdiff.py a.png b.png [-o diff.png] [--tol 8] [--max-bad 0.5]   (--max-bad in percent)
"""
import argparse
import os
import struct
import sys
import zlib

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from refrast import write_png  # noqa: E402


def read_png(path):
    data = open(path, "rb").read()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", path
    p, idat, hdr = 8, b"", None
    while p < len(data):
        n, t = struct.unpack(">I4s", data[p:p + 8])
        body = data[p + 8:p + 8 + n]
        if t == b"IHDR":
            hdr = struct.unpack(">IIBBBBB", body)
        elif t == b"IDAT":
            idat += body
        p += 12 + n
    w, h, depth, ctype, _, _, interlace = hdr
    assert depth == 8 and interlace == 0 and ctype in (2, 6), (path, hdr)
    ch = 4 if ctype == 6 else 3
    raw = zlib.decompress(idat)
    out = np.zeros((h, w * ch), np.uint8)
    prev = np.zeros(w * ch, np.int32)
    stride = w * ch + 1
    for y in range(h):
        f = raw[y * stride]
        line = np.frombuffer(raw, np.uint8, w * ch, y * stride + 1).astype(np.int32)
        if f == 0:
            cur = line
        elif f == 2:
            cur = (line + prev) & 255
        else:                                       # sub / average / paeth need a sequential pass
            cur = np.zeros_like(line)
            for x in range(w * ch):
                a = cur[x - ch] if x >= ch else 0
                b, c = prev[x], (prev[x - ch] if x >= ch else 0)
                if f == 1:
                    pr = a
                elif f == 3:
                    pr = (a + b) // 2
                else:
                    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                    pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                cur[x] = (line[x] + pr) & 255
        out[y] = cur
        prev = cur
    return out.reshape(h, w, ch)[..., :3]


def compare(a, b, tol=8):
    d = np.abs(a.astype(np.int32) - b.astype(np.int32))
    bad = (d.max(-1) > tol)
    return d.mean(), 100.0 * bad.mean(), d, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a"); ap.add_argument("b")
    ap.add_argument("-o", "--out")
    ap.add_argument("--tol", type=int, default=8)
    ap.add_argument("--max-bad", type=float, default=0.5)
    x = ap.parse_args()
    a, b = read_png(x.a), read_png(x.b)
    if a.shape != b.shape:
        print("size differs: %s vs %s" % (a.shape, b.shape)); sys.exit(1)
    mae, pct, d, bad = compare(a, b, x.tol)
    print("mean abs error %.3f, pixels off by more than %d: %.3f%%" % (mae, x.tol, pct))
    if x.out:
        vis = np.clip(d * 8, 0, 255).astype(np.uint8)
        vis[bad] = [255, 0, 255]
        write_png(x.out, vis)
    sys.exit(0 if pct <= x.max_bad else 1)


if __name__ == "__main__":
    main()
