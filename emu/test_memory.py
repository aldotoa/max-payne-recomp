"""Unit tests for the single-buffer guest memory: guest address A is host address Emu.mem_base + A.
Hand-assembled guest code; no game files needed.

Run:  .venv/bin/python emu/test_memory.py
"""
import ctypes
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mpemu


def test_host_write_visible_to_guest():
    """(a) bytes written through the host pointer are read back by Unicorn."""
    e = mpemu.Emu(".")
    addr = mpemu.HEAP_BASE + 0x100
    data = b"\x01\x02\x03\x04\xde\xad\xbe\xef"
    ctypes.memmove(e.mem_base + addr, data, len(data))
    assert bytes(e.uc.mem_read(addr, len(data))) == data
    print("ok  host-pointer write is visible to Unicorn reads")


def test_guest_write_visible_to_host():
    """(b) bytes written by Unicorn are visible in the host buffer."""
    e = mpemu.Emu(".")
    addr = mpemu.HEAP_BASE + 0x200
    data = b"\x10\x20\x30\x40\x50"
    e.uc.mem_write(addr, data)
    assert e.mem[addr:addr + len(data)] == data
    assert ctypes.string_at(e.mem_base + addr, len(data)) == data
    print("ok  Unicorn write is visible in the host buffer")


def test_guest_store_visible_in_buffer():
    """(c) guest code stores to the heap; the store shows up in e.mem and at mem_base + addr."""
    e = mpemu.Emu(".")
    code = e.alloc(64)
    target = mpemu.HEAP_BASE + 0x300
    # mov dword ptr [target], 0x12345678 ; mov eax, 42 ; ret
    body = (b"\xc7\x05" + struct.pack("<I", target) + struct.pack("<I", 0x12345678) +
            b"\xb8" + struct.pack("<I", 42) + b"\xc3")
    e.wr(code, body)
    assert e.call(code) == 42
    assert struct.unpack("<I", e.mem[target:target + 4])[0] == 0x12345678
    assert struct.unpack("<I", ctypes.string_at(e.mem_base + target, 4))[0] == 0x12345678
    print("ok  guest store to heap is visible in the host buffer")


def test_regions_inside_buffer():
    """(d) every mapped region lies inside the host buffer."""
    e = mpemu.Emu(".")
    e.map(0x00A00000, 0x2000)              # extra region, as the tests add
    assert e.regions, "no regions recorded"
    for addr, size in e.regions:
        assert addr % mpemu.PAGE == 0 and size % mpemu.PAGE == 0 and size > 0, (hex(addr), size)
        assert addr + size <= len(e.mem), (hex(addr), size)
    print("ok  all %d regions lie inside the %d-byte buffer" % (len(e.regions), len(e.mem)))


def test_map_rounds_outwards():
    """map() page-aligns: an unaligned range maps the whole pages it touches."""
    e = mpemu.Emu(".")
    e.map(0x00B00123, 0x10)
    assert (0x00B00000, 0x1000) in e.regions, e.regions[-1]
    e.uc.mem_write(0x00B00FFF, b"\x77")
    assert e.mem[0x00B00FFF] == 0x77
    print("ok  map() rounds to whole pages")


if __name__ == "__main__":
    test_host_write_visible_to_guest()
    test_guest_write_visible_to_host()
    test_guest_store_visible_in_buffer()
    test_regions_inside_buffer()
    test_map_rounds_outwards()
    print("all memory tests passed")
