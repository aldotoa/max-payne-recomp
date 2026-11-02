#!/usr/bin/env python3
"""M2 bring-up: run Max Payne's original x86-32 modules under Unicorn on arm64.

Pieces: PE loader (map, relocate, resolve imports across loaded modules), a TEB/PEB/stack/heap
set-up, and an HLE dispatcher: every import that is not provided by another loaded module is
bound to a stub address; when the CPU lands on a stub, a Python handler runs and returns to the
caller with the right calling convention.

Prototype in Python for fast iteration; the loader/HLE design is meant to be ported to the C++
host later. Game files are read from the user's game directory only.
"""
import collections
import ctypes
import mmap
import os
import struct
import sys
import threading
import time

import pefile
from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_MODE_32, UC_PROT_ALL,
                     Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_FPCW,
                               UC_X86_REG_FS, UC_X86_REG_GDTR, UC_X86_REG_CS, UC_X86_REG_DS,
                               UC_X86_REG_ES, UC_X86_REG_SS, UC_X86_REG_EBX, UC_X86_REG_ESI,
                               UC_X86_REG_EDI, UC_X86_REG_EFLAGS, UC_X86_REG_FPSW, UC_X86_REG_FPTAG,
                               UC_X86_REG_FP0, UC_X86_REG_FP1, UC_X86_REG_FP2, UC_X86_REG_FP3,
                               UC_X86_REG_FP4, UC_X86_REG_FP5, UC_X86_REG_FP6, UC_X86_REG_FP7)

PAGE = 0x1000
STACK_TOP = 0x00300000
STACK_SIZE = 0x00200000
TEB = 0x7FFDE000
SCRATCH = 0x7FFDB000
PEB = 0x7FFDF000
STUB_BASE = 0x7F000000
STUB_SIZE = 0x00100000
STUB_STRIDE = 16
# Direct HLE calls (runtime.c hle_direct, Emu.hle_direct): the result codes, and the handlers lifted code calls
# without the emulator. Each must be an ordinary handler: no coroutine, no register access, no emu_stop.
HLE_DECLINE, HLE_DONE, HLE_NEVER, HLE_HALT = 0, 1, 2, 3
HLE_DIRECT = {("KERNEL32.DLL", n) for n in (
    "QueryPerformanceCounter", "WaitForSingleObject", "ReleaseMutex",
    # what the lifted MSVCRT heap, _getptd and MFC42 operator new/delete call (H42)
    "TlsGetValue", "TlsSetValue", "GetLastError", "SetLastError", "GetCurrentThreadId",
    "InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
    "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize")}
HEAP_BASE = 0x20000000
HEAP_SIZE = 0x20000000

# Fixed bases for the game's DLLs (they all prefer 0x10000000) and system DLLs.
MODULE_BASES = {
    "rlmfc.dll": 0x10000000,
    "e2mfc.dll": 0x10100000,
    "grphmfc.dll": 0x10200000,
    "sndmfc.dll": 0x10300000,
    "e2_d3d8_driver_mfc.dll": 0x10400000,
}

_now_ns = time.perf_counter_ns                  # Emu.hle_direct's per-handler timing (H43)

HLE = {}

# Differential mode (emu/native.py Native.run_diff): one HLE call as the reference run made it. key is (dll, name),
# sp the stack pointer at the stub, args the argument words, regs the register values after the handler
# ({reg id: value}), writes the guest bytes the handler wrote ({addr: byte}). unrep: the record cannot be replayed.
class HleRec:
    __slots__ = ("key", "sp", "args", "unrep", "regs", "writes")

    def __init__(self, key, sp, args, unrep, regs, writes):
        self.key, self.sp, self.args, self.unrep, self.regs, self.writes = key, sp, args, unrep, regs, writes


# registers an HLE call can change: the GPRs, EFLAGS, the x87 control, status and tag words, and the eight FP registers
SNAP_REGS = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
             UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP, UC_X86_REG_EFLAGS, UC_X86_REG_FPSW,
             UC_X86_REG_FPCW, UC_X86_REG_FPTAG,
             UC_X86_REG_FP0, UC_X86_REG_FP1, UC_X86_REG_FP2, UC_X86_REG_FP3, UC_X86_REG_FP4,
             UC_X86_REG_FP5, UC_X86_REG_FP6, UC_X86_REG_FP7]


def write_runs(writes):
    """Apply {addr: byte} through Emu.wr-style writes, one call per run of consecutive addresses. Returns the runs."""
    return [(start, bytes(buf)) for start, buf in _runs_of(writes)]


def _runs_of(writes):
    if not writes:
        return []
    addrs = sorted(writes)
    out = []
    start = prev = addrs[0]
    buf = bytearray([writes[start]])
    for a in addrs[1:]:
        if a == prev + 1:
            buf.append(writes[a])
        else:
            out.append((start, buf))
            start = a
            buf = bytearray([writes[a]])
        prev = a
    out.append((start, buf))
    return out


STRING_ARG_APIS = {"GetFileAttributesA", "GetFileAttributesW", "CreateFileA", "CreateFileW",
                   "SetCurrentDirectoryA", "SetCurrentDirectoryW", "FindFirstFileA", "FindFirstFileW",
                   "GetFullPathNameA", "GetFullPathNameW", "CreateDirectoryA", "CreateDirectoryW",
                   "LoadLibraryA", "GetModuleHandleA", "GetShortPathNameA", "CopyFileA", "DeleteFileA"}


def hle(dll, name, nargs, cc="stdcall"):
    def deco(fn):
        HLE[(dll.upper(), name)] = (fn, nargs, cc)
        return fn
    return deco


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


class Module:
    def __init__(self, name, path, base, pe, data):
        self.name, self.path, self.base, self.pe, self.data = name, path, base, pe, data
        self.exports = {}      # name -> va
        self.ord_exports = {}  # ordinal -> va
        self.size = align_up(pe.OPTIONAL_HEADER.SizeOfImage)

    @property
    def entry(self):
        ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        return self.base + ep if ep else 0


class Unimplemented(Exception):
    pass


class ApiLog:
    """The API log: a bounded deque of lines. An HLE call's line is kept as its (dll, name, args, res) record and
    formatted only when the log is read (iteration, indexing), so a call costs one tuple, not a string format (H43).
    Lines that need guest memory (string arguments) are formatted at append time by the caller."""

    def __init__(self, maxlen=20000):
        self._d = collections.deque(maxlen=maxlen)
        self.append = self._d.append
        self.clear = self._d.clear

    @property
    def maxlen(self):
        return self._d.maxlen

    @staticmethod
    def line(x):
        if x.__class__ is str:
            return x
        dll, name, args, res = x
        return "%s!%s(%s) -> %s" % (dll, name, ", ".join("0x%x" % a for a in args), hex(res & 0xFFFFFFFF))

    def __len__(self):
        return len(self._d)

    def __iter__(self):
        return map(self.line, list(self._d))

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self.line(x) for x in list(self._d)[i]]
        return self.line(self._d[i])


class GuestCall:
    """Yielded by an HLE generator: run guest function `addr(*args)`; its return value is sent back."""
    def __init__(self, addr, args=(), cc="cdecl"):
        self.addr, self.args, self.cc = addr, tuple(args), cc


class ResumeAt:
    """Returned by an HLE generator to continue guest execution at (eip, esp, eax) instead of returning."""
    def __init__(self, eip, esp, eax):
        self.eip, self.esp, self.eax = eip, esp, eax


class Coro:
    """An HLE call implemented as a generator that can call back into guest code (SEH, RtlUnwind)."""
    def __init__(self, gen, sp0, ret, pop, name):
        self.gen, self.sp0, self.ret, self.pop, self.name = gen, sp0, ret, pop, name
        self.call = None


class FastUc:
    """The hot host-call path talks to the Unicorn C library directly with preallocated buffers. Through the
    Python binding each register access or small read costs 2-3 us of wrapper code, and every host call makes
    about eight of them."""
    def __init__(self, uc):
        from unicorn.unicorn_py3.unicorn import uclib
        self.lib, self.h = uclib, uc._uch
        self.v = ctypes.c_uint32()
        self.vp = ctypes.byref(self.v)
        self.buf = ctypes.create_string_buffer(256)

    def get(self, reg):
        self.lib.uc_reg_read(self.h, reg, self.vp)
        return self.v.value

    def set(self, reg, val):
        self.v.value = val & 0xFFFFFFFF
        self.lib.uc_reg_write(self.h, reg, self.vp)

    def read(self, addr, n):
        """n <= 256 bytes; raises UcError like Uc.mem_read."""
        err = self.lib.uc_mem_read(self.h, addr, self.buf, n)
        if err:
            raise UcError(err)
        return self.buf.raw[:n]


class FreeList:
    """Free blocks of the guest heap: address-ordered, coalesced with their neighbours, with size classes
    (powers of two) so an allocation looks only at blocks that can hold it."""

    def __init__(self):
        self.start = {}                 # block address -> size
        self.end = {}                   # block end address -> block address
        self.classes = collections.defaultdict(set)   # size class -> block addresses
        self.total = 0

    @staticmethod
    def _cls(size):
        return size.bit_length()

    def _add(self, p, size):
        self.start[p] = size
        self.end[p + size] = p
        self.classes[self._cls(size)].add(p)
        self.total += size

    def _remove(self, p):
        size = self.start.pop(p)
        del self.end[p + size]
        self.classes[self._cls(size)].discard(p)
        self.total -= size
        return size

    def put(self, p, size):
        q = self.end.get(p)                 # free block ending where this one starts
        if q is not None:
            size += self._remove(q)
            p = q
        if p + size in self.start:          # free block starting where this one ends
            size += self._remove(p + size)
        self._add(p, size)

    def take(self, size):
        """Lowest-addressed block of the smallest class that fits; the rest stays free. None when none fits."""
        c = self._cls(size)
        while c <= 32:
            blocks = self.classes.get(c)
            if blocks:
                fits = [b for b in blocks if self.start[b] >= size]
                if fits:
                    p = min(fits)
                    have = self._remove(p)
                    if have > size:
                        self._add(p + size, have - size)
                    return p
            c += 1
        return None


class PyHeap:
    """The guest heap in Python: live blocks (address -> size, and the 16-byte rounded capacity of alloc() blocks),
    the FreeList, and a bump pointer (next) for fresh memory. native.CHeap is the same allocator in C (lift/runtime/
    heap.c), with the same block choices; Emu.heap is one or the other."""

    def __init__(self, base, limit):
        self.next = base
        self.limit = limit
        self.blocks = {}                 # ptr -> size (live blocks: alloc and VirtualAlloc)
        self.caps = {}                   # alloc() ptr -> rounded capacity (what free() gives back)
        self.free_list = FreeList()      # freed alloc() blocks, reused before next grows

    def alloc(self, size):
        """(p, reused) for a block of size >= 1 bytes; reused blocks hold old bytes. MemoryError when exhausted."""
        cap = align_up(size, 16)
        p = self.free_list.take(cap)
        reused = p is not None
        if not reused:
            p = align_up(self.next, 16)
            if p + cap > self.limit:
                raise MemoryError(self.exhausted())
            self.next = p + cap
        self.blocks[p] = size
        self.caps[p] = cap
        return p, reused

    def exhausted(self):
        return "guest heap exhausted (%d MB live in %d blocks, %d MB free but fragmented)" % (
            sum(self.caps.values()) >> 20, len(self.caps), self.free_list.total >> 20)

    def free(self, p):
        cap = self.caps.pop(p, None)
        if cap is None:
            return False
        self.blocks.pop(p, None)
        self.free_list.put(p, cap)
        return True

    def get(self, p):
        """(size, cap) of the live block p (cap 0 for a VirtualAlloc block), or None."""
        size = self.blocks.get(p)
        return None if size is None else (size, self.caps.get(p, 0))

    def resize(self, p, size):
        self.blocks[p] = size

    def reserve(self, size, record):
        """Page-aligned memory from the bump pointer: VirtualAlloc (record: the block's size is kept) or a file view."""
        p = align_up(self.next, PAGE)
        self.next = p + align_up(size if record else max(size, 1), PAGE)
        if record:
            self.blocks[p] = size
        return p

    def __len__(self):
        return len(self.blocks)

    def live(self):
        return [(p, n, self.caps.get(p, 0)) for p, n in self.blocks.items()]

    def free_blocks(self):
        return list(self.free_list.start.items())


class HeapSizes:
    """Emu.heap_blocks: the live blocks' sizes as a read-only mapping (ptr -> size), whichever heap is in use."""

    def __init__(self, heap):
        self.heap = heap

    def get(self, p, default=None):
        g = self.heap.get(p)
        return default if g is None else g[0]

    def __getitem__(self, p):
        g = self.heap.get(p)
        if g is None:
            raise KeyError(p)
        return g[0]

    def __contains__(self, p):
        return self.heap.get(p) is not None

    def __len__(self):
        return len(self.heap)

    def __iter__(self):
        return iter([p for p, _, _ in self.heap.live()])


PAGE_SHIFT = 12
_ONES = b"\x01" * PAGE


class _UndoPage:
    """One 4 KB guest page of an undo log: old[i] is the byte at page offset i before its first write in this log,
    seen[i] is 1 once byte i has been written (so old[i] is valid), new is a snapshot of the page at undo_end."""
    __slots__ = ("old", "seen", "new")

    def __init__(self):
        self.old = bytearray(PAGE)
        self.seen = bytearray(PAGE)
        self.new = None


def _runs(seen):
    """(start, end) offsets of the runs of 1s in a page's seen mask."""
    j, n = 0, len(seen)
    while True:
        s = seen.find(1, j)
        if s < 0:
            return
        e = seen.find(0, s)
        if e < 0:
            e = n
        yield s, e
        j = e


class UndoLog:
    """What one undo_begin/undo_end pair recorded: the CPU state at begin, and the old value of every guest byte
    written while it was active. Per-page bytearrays keep the per-write cost to a dict lookup and a bytearray
    search; a 512 MB heap costs memory only for the pages that are actually written."""

    def __init__(self, mem, cpu):
        self._mem = mem
        self.cpu = cpu            # (uc context, explicit register values) saved at begin
        self.pages = {}           # page index -> _UndoPage
        self.ended = False

    def _finish(self):
        for pi, pg in self.pages.items():
            base = pi << PAGE_SHIFT
            pg.new = bytes(self._mem[base:base + PAGE])

    def writes(self):
        """{guest_addr: value} for every byte written while this log was active, with the value it has now (or had
        at undo_end, once ended). Bytes written back to their old value are included."""
        out = {}
        for pi, pg in self.pages.items():
            base = pi << PAGE_SHIFT
            cur = pg.new if pg.new is not None else self._mem[base:base + PAGE]
            for s, e in _runs(pg.seen):
                for j in range(s, e):
                    out[base + j] = cur[j]
        return out


# CPU registers saved next to uc.context_save(): the context covers them, the explicit copy makes the
# guarantee visible and is compared by the tests.
_UNDO_REGS = (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI,
              UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
              UC_X86_REG_FS, UC_X86_REG_GDTR, UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG,
              UC_X86_REG_FP0, UC_X86_REG_FP1, UC_X86_REG_FP2, UC_X86_REG_FP3, UC_X86_REG_FP4,
              UC_X86_REG_FP5, UC_X86_REG_FP6, UC_X86_REG_FP7)


class _FastTls:
    """Emu.tls once the TLS slots live in lift/runtime/hle_fast.c (native.HleFast, H60): the dict operations the TLS
    handlers use. Slots past C's range stay in a Python dict (extra)."""

    def __init__(self, fast, old):
        self.fast, self.extra = fast, {}
        for i, v in old.items():
            self[i] = v

    def __setitem__(self, i, v):
        if not self.fast.set(7, i, 0, v):
            self.extra[i] = v

    def get(self, i, default=None):
        r = self.fast.get(7, i)
        return r[0] if r is not None else self.extra.get(i, default)

    def pop(self, i, default=None):
        r = self.fast.get(7, i)
        if r is None:
            return self.extra.pop(i, default)
        self.fast.set(7, i, 0, 0, on=False)
        return r[0]

    def items(self):
        import native
        return [(i, r[0]) for i in range(native.TLS_SLOTS) for r in (self.fast.get(7, i),) if r is not None] + \
            list(self.extra.items())


class Emu:
    _k32_fast = None        # native.HleFast once the last error and the TLS slots live in C (attach_fast_k32)

    @property
    def last_error(self):
        f = self._k32_fast
        return f.get(6)[0] if f is not None else self._last_error

    @last_error.setter
    def last_error(self, v):
        f = self._k32_fast
        if f is not None:
            f.set(6, 0, 0, v)
        else:
            self._last_error = v

    def attach_fast_k32(self, fast):
        """Move the last error and the TLS slots into lift/runtime/hle_fast.c, which serves TlsGetValue, TlsSetValue,
        GetLastError and SetLastError from lifted code (H60). The Python handlers keep using e.last_error and e.tls."""
        le = self.last_error
        self._k32_fast = fast
        self.last_error = le
        self.tls = _FastTls(fast, self.tls)

    def __init__(self, game_dir):
        self.game_dir = os.path.abspath(game_dir)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self._undo_stack = []                      # active UndoLogs, outermost first
        self._undo_hook = None                     # the UC_HOOK_MEM_WRITE handle while any log is active
        # All guest memory lives in one host mapping: guest address A is host address mem_base + A.
        # Anonymous private memory is committed lazily by the OS, so reserving the whole 4 GB costs
        # nothing until pages are touched. The buffer export (from_buffer) keeps the mmap alive
        # with this Emu; it is never closed.
        self.mem = mmap.mmap(-1, 1 << 32, flags=mmap.MAP_PRIVATE | mmap.MAP_ANON,
                             prot=mmap.PROT_READ | mmap.PROT_WRITE)
        self._mem_export = ctypes.c_char.from_buffer(self.mem)
        self.mem_base = ctypes.addressof(self._mem_export)
        self.regions = []                          # (addr, size) of every mapped guest region
        self.fast = FastUc(self.uc)
        self.modules = collections.OrderedDict()   # lower name -> Module
        self.stubs = []                            # index -> (dll, name)
        self.stub_index = {}                       # (dll, name) -> va
        self.apilog = ApiLog(maxlen=20000)
        self.fatal = None
        self.last_error = 0
        self.heap = PyHeap(HEAP_BASE, HEAP_BASE + HEAP_SIZE)   # the guest heap; native.CHeap once the fast path runs
        self.tls = {}
        self.tls_next = 0
        self.handles = {}
        self.handle_next = 0x200
        self.unresolved = collections.Counter()
        self.exit_code = None
        self.mfc_lenient = False
        self.mfc_calls = collections.Counter()
        self.mfc_ret = None
        self.mfc_retvals = {}       # ordinal -> callable(emu) -> int, for lenient MFC calls that need a real value
        self.stop_stubs = set()
        self.pc_trace = None
        self.stub_counts = collections.Counter()
        self.hle_direct_ns = collections.Counter()   # (dll, name) -> ns in the handler, direct calls only (H43)
        self.hle_direct_n = collections.Counter()    # (dll, name) -> direct calls
        self.hle_direct_total_ns = 0                 # all of Emu.hle_direct for those calls (handler + unpack + log)
        self.coros = []
        self.budget_exhausted = False
        self._call_base_sp = None
        self.native = None                         # emu/native.py Native bound to this Emu (M5), if any
        self.on_module_loaded = []                 # callbacks(mod): run by load_library on a first load (see there)
        self._native_pending = None                # VA of a native function reached by guest code (see _drive)
        self._in_hook = False                      # True while a Unicorn hook runs: emu_start is then forbidden
        self._drive_depth = 0                      # active _drive loops (native slots are only valid inside one)
        self._diff_active = False                  # differential mode: the entry hooks pass through (native.py)
        self._hle_mode = None                      # differential mode HLE: None, "record" or "replay" (_on_stub_mode)
        self._hle_rec = None                       # the list of HleRec being written (record) or replayed
        self._hle_cursor = 0                       # next HleRec to replay
        self._hle_div = None                       # the first divergence of the current replay
        self._diff_slot_addr = None                # stub that stops the emulator when a diffed function returns
        self._setup_memory()

    # ---------------------------------------------------------------- memory helpers
    def map(self, addr, size):
        """Map guest [addr, addr+size) (page-aligned outwards) to its place in the host buffer."""
        start = addr & ~(PAGE - 1)
        end = (addr + size + PAGE - 1) & ~(PAGE - 1)
        self.uc.mem_map_ptr(start, end - start, UC_PROT_ALL, self.mem_base + start)
        self.regions.append((start, end - start))
        if self.native is not None:       # the native side's copy (CRT helpers, thunk shortcut): DLLs loaded later
            self.native.sync_regions()

    def _setup_memory(self):
        uc = self.uc
        self.map(STACK_TOP - STACK_SIZE, STACK_SIZE)
        self.map(TEB, PAGE * 2)
        self.map(SCRATCH, PAGE)
        self.map(STUB_BASE, STUB_SIZE)
        self.map(HEAP_BASE, HEAP_SIZE)
        # stub 0 is the "return to host" address
        self.stubs.append(("<host>", "exit"))
        self.wr(STUB_BASE, b"\xf4" * STUB_STRIDE)
        # stub 1: where guest functions called on behalf of an HLE coroutine return to
        self.stubs.append(("<host>", "resume"))
        self.wr(STUB_BASE + STUB_STRIDE, b"\xf4" * STUB_STRIDE)
        # TEB / PEB (just enough for CRT and SEH)
        teb = bytearray(PAGE)
        struct.pack_into("<I", teb, 0x00, 0xFFFFFFFF)         # SEH chain end
        struct.pack_into("<I", teb, 0x04, STACK_TOP)
        struct.pack_into("<I", teb, 0x08, STACK_TOP - STACK_SIZE)
        struct.pack_into("<I", teb, 0x18, TEB)
        struct.pack_into("<I", teb, 0x20, 0x100)              # pid
        struct.pack_into("<I", teb, 0x24, 0x104)              # tid
        struct.pack_into("<I", teb, 0x30, PEB)
        self.wr(TEB, bytes(teb))
        peb = bytearray(PAGE)
        struct.pack_into("<I", peb, 0xA4, 5)                  # OSMajorVersion
        struct.pack_into("<I", peb, 0xA8, 1)                  # OSMinorVersion
        struct.pack_into("<H", peb, 0xAC, 2600)               # OSBuildNumber
        struct.pack_into("<I", peb, 0xB0, 2)                  # OSPlatformId (NT)
        self.wr(PEB, bytes(peb))
        self._set_fs(TEB)
        uc.reg_write(UC_X86_REG_FPCW, 0x027F)                 # 53-bit precision, round-nearest
        uc.reg_write(UC_X86_REG_ESP, STACK_TOP - 0x1000)
        uc.hook_add(UC_HOOK_CODE, self._on_stub, begin=STUB_BASE, end=STUB_BASE + STUB_SIZE - 1)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED, self._on_unmapped)

    def _set_fs(self, base):
        """32-bit Unicorn ignores FS_BASE. Build a small GDT (flat code/data + FS=TEB) and load it."""
        gdt = 0x7FFDC000
        self.map(gdt, PAGE)

        def desc(b, limit, access, flags):
            return struct.pack("<HHBBBB", limit & 0xFFFF, b & 0xFFFF, (b >> 16) & 0xFF, access,
                               (flags << 4) | ((limit >> 16) & 0xF), (b >> 24) & 0xFF)

        self.wr(gdt + 8 * 1, desc(0, 0xFFFFF, 0x9B, 0xC))      # flat code, ring 0
        self.wr(gdt + 8 * 2, desc(0, 0xFFFFF, 0x93, 0xC))      # flat data, ring 0
        self.wr(gdt + 8 * 3, desc(base, 0xFFF, 0x93, 0x4))     # FS -> TEB
        self.uc.reg_write(UC_X86_REG_GDTR, (0, gdt, 8 * 4 - 1, 0))
        self.uc.reg_write(UC_X86_REG_CS, 1 << 3)
        for r in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(r, 2 << 3)
        self.uc.reg_write(UC_X86_REG_FS, 3 << 3)

    def rd(self, addr, n):
        if n <= 256:
            return self.fast.read(addr, n)
        return bytes(self.uc.mem_read(addr, n))

    def wr(self, addr, data):
        """Host-side write of guest memory. Every host write path goes through here (or calls _note_write itself)
        so an active undo log sees it."""
        data = bytes(data)
        if self._undo_stack:
            self._note_write(addr, len(data))
        self.uc.mem_write(addr, data)

    def rd32(self, addr):
        return struct.unpack("<I", self.rd(addr, 4))[0]

    def wr32(self, addr, v):
        self.wr(addr, struct.pack("<I", v & 0xFFFFFFFF))

    # ---------------------------------------------------------------- undo log
    # Rollback restores guest memory and the CPU registers. It does NOT roll back host Python state: the heap
    # allocator (Emu.heap), handles, open files, DirectX/DirectSound objects,
    # coroutines, apilog and the other winsys/HLE tables are left as they are after the logged code ran. The
    # differential mode has to snapshot or reset those itself; a rollback only undoes what the guest and the
    # host memory writes did to the 4 GB guest address space and to the x86 registers.
    def undo_begin(self):
        """Start recording undo information. Nesting is allowed: every active log records every write. Returns the
        UndoLog (the token that undo_end must be given). Call between guest runs, not from inside an HLE handler."""
        if not self._undo_stack:
            self._undo_hook = self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_undo_write)
            self.uc.ctl_flush_tb()          # blocks translated before the hook was added have no hook call
        log = UndoLog(self.mem, self._save_cpu())
        self._undo_stack.append(log)
        return log

    def undo_end(self, mark):
        """Stop recording the log `mark` (must be the innermost active one); returns it, with its final values."""
        if not self._undo_stack or self._undo_stack[-1] is not mark:
            raise RuntimeError("undo_end: not the innermost active undo log")
        self._undo_stack.pop()
        mark.ended = True
        mark._finish()
        if not self._undo_stack:
            self._remove_undo_hook()
        return mark

    def _remove_undo_hook(self):
        """Unicorn does not unlink a deleted hook at once: uc_hook_del queues it, and the queue is emptied at the end
        of the next uc_emu_start. Its memory-write check (and so the store slow path) stays on until then, and the
        translated blocks keep the hook call. So: delete, run a start that executes nothing (begin == until at the
        stub region, EIP put back), then drop the translated blocks so they are rebuilt without the hook."""
        uc = self.uc
        uc.hook_del(self._undo_hook)
        self._undo_hook = None
        eip = uc.reg_read(UC_X86_REG_EIP)
        uc.emu_start(STUB_BASE, STUB_BASE)
        uc.reg_write(UC_X86_REG_EIP, eip)
        uc.ctl_flush_tb()

    def undo_rollback(self, log):
        """Restore every byte the log recorded and the CPU state saved at its undo_begin. The log must have ended.
        The restored bytes are noted in any log still active, so outer logs stay exact."""
        if not log.ended:
            raise RuntimeError("undo_rollback: the log is still active; call undo_end first")
        mem = self.mem
        restored = False
        for pi, pg in log.pages.items():
            base = pi << PAGE_SHIFT
            for s, e in _runs(pg.seen):
                if self._undo_stack:
                    self._note_write(base + s, e - s)
                mem[base + s:base + e] = pg.old[s:e]
                restored = True
        if restored:
            self.uc.ctl_flush_tb()          # restored bytes may be code that translated blocks were built from
        self._restore_cpu(log.cpu)

    def _on_undo_write(self, uc, access, address, size, value, user):
        # UC_HOOK_MEM_WRITE runs before the store lands, so self.mem still holds the old bytes.
        self._note_write(address, size)

    def _note_write(self, addr, n):
        """Record the old bytes of guest [addr, addr+n) in every active log, for the bytes they have not recorded
        yet. Must run before the write lands."""
        if n <= 0:
            return
        mem = self.mem
        end = addr + n
        for log in self._undo_stack:
            pages = log.pages
            a = addr
            while a < end:
                pi = a >> PAGE_SHIFT
                stop = min(end, (pi + 1) << PAGE_SHIFT)
                pg = pages.get(pi)
                if pg is None:
                    pg = pages[pi] = _UndoPage()
                off = a & (PAGE - 1)
                lim = off + (stop - a)
                seen = pg.seen
                if seen.find(0, off, lim) >= 0:             # some byte of this span is new to the log
                    if seen.find(1, off, lim) < 0:           # all of it is new (the common case)
                        pg.old[off:lim] = mem[a:stop]
                        seen[off:lim] = _ONES[:lim - off]
                    else:
                        base = pi << PAGE_SHIFT
                        for j in range(off, lim):
                            if not seen[j]:
                                pg.old[j] = mem[base + j]
                                seen[j] = 1
                a = stop

    def _save_cpu(self):
        uc = self.uc
        return (uc.context_save(), {r: uc.reg_read(r) for r in _UNDO_REGS})

    def _restore_cpu(self, saved):
        ctx, regs = saved
        uc = self.uc
        uc.context_restore(ctx)
        for r, v in regs.items():
            if uc.reg_read(r) != v:             # the context already restores these; the explicit copy is a check
                uc.reg_write(r, v)

    def cstr(self, addr, limit=4096):
        if not addr:
            return ""
        out = bytearray()
        while len(out) < limit:
            b = self.rd(addr + len(out), 1)
            if b == b"\0":
                break
            out += b
        return out.decode("latin1")

    def wstr(self, addr, limit=4096):
        out = bytearray()
        while len(out) < limit * 2:
            b = self.rd(addr + len(out), 2)
            if b == b"\0\0":
                break
            out += b
        return out.decode("utf-16le", "replace")

    def put_cstr(self, s, extra=0):
        p = self.alloc(len(s) + 1 + extra)
        self.wr(p, s.encode("latin1") + b"\0")
        return p

    def alloc(self, size, zero=True):
        """Guest heap block of `size` bytes, 16-byte aligned. Freed blocks are reused (first fit, split, coalesced);
        the heap only grows when none fits. A reused block is zeroed unless zero=False (fresh memory is zero)."""
        size = max(size, 1)
        p, reused = self.heap.alloc(size)
        if reused and zero:
            self.wr(p, bytes(align_up(size, 16)))
        return p

    @property
    def heap_next(self):
        """The heap's bump pointer: where fresh memory starts."""
        return self.heap.next

    @property
    def heap_blocks(self):
        """Live heap blocks, ptr -> size (alloc and VirtualAlloc blocks)."""
        return HeapSizes(self.heap)

    def free(self, p):
        """Return an alloc() block to the heap. Unknown pointers (NULL, double frees, VirtualAlloc/file-view
        memory, host-owned objects) are ignored, as they were when nothing was ever freed."""
        return self.heap.free(p)

    def enable_pc_trace(self, n=40):
        """Debug aid: remember the last n executed instruction addresses (slow; use only to diagnose)."""
        self.pc_trace = collections.deque(maxlen=n)
        self.uc.hook_add(UC_HOOK_CODE, lambda uc, a, sz, u: self.pc_trace.append(a))

    def stop_at(self, va, label):
        """Stop emulation when execution reaches `va` (used to halt at AfxWinMain instead of running MFC's loop)."""
        def cb(uc, addr, size, user):
            self.fatal = "reached %s (0x%x)" % (label, addr)
            uc.emu_stop()
        self.uc.hook_add(UC_HOOK_CODE, cb, begin=va, end=va)

    def ecx(self):
        return self.uc.reg_read(UC_X86_REG_ECX)

    def empty_cstring(self):
        """Pointer to the character data of a shared empty MFC CString (header: refs, length, alloc)."""
        if not hasattr(self, "_empty_cs"):
            p = self.alloc(16)
            self.wr(p, struct.pack("<iii", -1, 0, 0) + b"\0")
            self._empty_cs = p + 12
        return self._empty_cs

    def new_cstring(self, text):
        """Allocate an MFC CString buffer (refs, length, alloc, chars) and return the char-data pointer."""
        raw = text.encode("latin1")
        p = self.alloc(12 + len(raw) + 1)
        self.wr(p, struct.pack("<iii", 1, len(raw), len(raw)) + raw + b"\0")
        return p + 12

    def pop_args(self, n):
        sp = self.uc.reg_read(UC_X86_REG_ESP)
        return [self.rd32(sp + 4 + 4 * i) for i in range(n)]

    # ---------------------------------------------------------------- loader
    def host_path(self, guest):
        """Map a guest path (C:\\MaxPayne\\x, relative, either slash) onto the game dir, case-insensitively."""
        p = guest.replace("\\", "/")
        if len(p) > 1 and p[1] == ":":
            p = p[2:]
        if p.lower().startswith("/maxpayne/"):
            p = p[len("/maxpayne/"):]
        p = p.lstrip("/")
        cur = self.game_dir
        for part in [x for x in p.split("/") if x and x != "."]:
            if part == "..":
                cur = os.path.dirname(cur)
                continue
            try:
                names = os.listdir(cur)
            except OSError:
                return os.path.join(cur, part)
            hit = next((n for n in names if n.lower() == part.lower()), None)
            cur = os.path.join(cur, hit if hit else part)
        return cur

    def load_module(self, rel, base=None):
        path = os.path.join(self.game_dir, rel)
        name = os.path.basename(rel).lower()
        data = open(path, "rb").read()
        pe = pefile.PE(data=data)
        pref = pe.OPTIONAL_HEADER.ImageBase
        base = base or MODULE_BASES.get(name, pref)
        mod = Module(name, path, base, pe, data)
        uc = self.uc
        self.map(base, mod.size)
        self.wr(base, data[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for s in pe.sections:
            raw = data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
            vsz = max(s.Misc_VirtualSize, s.SizeOfRawData)
            self.wr(base + s.VirtualAddress, raw[:vsz])
        delta = (base - pref) & 0xFFFFFFFF
        if delta and hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
            for blk in pe.DIRECTORY_ENTRY_BASERELOC:
                for e in blk.entries:
                    if e.type == 3:  # IMAGE_REL_BASED_HIGHLOW
                        a = base + e.rva
                        self.wr32(a, self.rd32(a) + delta)
        d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if d:
            for sym in d.symbols:
                va = base + sym.address
                if sym.name:
                    mod.exports[sym.name.decode()] = va
                mod.ord_exports[sym.ordinal] = va
        self.modules[name] = mod
        return mod

    def stub_for(self, dll, name):
        key = (dll.upper(), name)
        if key in self.stub_index:
            return self.stub_index[key]
        idx = len(self.stubs)
        if idx * STUB_STRIDE >= STUB_SIZE:
            raise MemoryError("stub region full")
        va = STUB_BASE + idx * STUB_STRIDE
        self.stubs.append(key)
        self.stub_index[key] = va
        self.wr(va, b"\xf4" * STUB_STRIDE)
        return va

    def find_module(self, dllname):
        n = dllname.lower()
        if n in self.modules:
            return self.modules[n]
        return None

    def resolve_imports(self, mod):
        pe = mod.pe
        for ent in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = ent.dll.decode()
            target = self.find_module(dll)
            for imp in ent.imports:
                label = imp.name.decode() if imp.name else "#%d" % imp.ordinal
                va = None
                if target:
                    va = (target.exports.get(label) if imp.name
                          else target.ord_exports.get(imp.ordinal))
                if va is None:
                    va = self.stub_for(dll, label)
                    self.unresolved[(dll.upper(), label)] += 1
                # imp.address is relative to the file's preferred base, not our load base
                self.wr32(mod.base + (imp.address - pe.OPTIONAL_HEADER.ImageBase), va)
        # Delay imports (MFC42.DLL: OLE32, ADVAPI32, COMCTL32, WININET, ...) are bound now, as ordinary imports, instead
        # of by the module's __delayLoadHelper on first call (LoadLibraryA + GetProcAddress, which gave NULL for every
        # DLL outside FAKE_DLLS). Lifted code then never meets the resolver stubs (lift/functions.py delay_imports).
        for ent in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            dll = ent.dll.decode()
            target = self.find_module(dll)
            for imp in ent.imports:
                label = imp.name.decode() if imp.name else "#%d" % imp.ordinal
                va = None
                if target:
                    va = (target.exports.get(label) if imp.name
                          else target.ord_exports.get(imp.ordinal))
                if va is None:
                    va = self.stub_for(dll, label)
                self.wr32(mod.base + (imp.address - pe.OPTIONAL_HEADER.ImageBase), va)

    def resolve_name(self, dll, name):
        m = self.find_module(dll) if dll else None
        if m:
            return m.exports.get(name, 0)
        for mod in self.modules.values():
            if name in mod.exports:
                return mod.exports[name]
        if (dll and (dll.upper(), name) in HLE):
            return self.stub_for(dll, name)
        return 0

    # ---------------------------------------------------------------- HLE dispatch
    def _on_stub(self, uc, addr, size, user):
        self._in_hook = True
        try:
            if self._hle_mode is None:
                self._on_stub_body(uc, addr, size, user)
            else:
                self._on_stub_mode(uc, addr)
        finally:
            self._in_hook = False

    def _on_stub_mode(self, uc, addr):
        """Differential mode: an HLE call is recorded (reference run) or replayed (native run) instead of being
        handled as usual. Slots 0 and 1, native slots and the diff return slot are never HLE calls."""
        idx = (addr - STUB_BASE) // STUB_STRIDE
        stubs = self.stubs
        if idx == 1:
            if self._hle_mode == "record":
                self._hle_rec.append(HleRec(("<resume>", ""), 0, (), True, {}, {}))
                return self._on_stub_body(uc, addr, 0, None)
            return self._hle_diverge(uc, "an HLE coroutine was resumed by native code")
        if idx < 2 or idx >= len(stubs) or stubs[idx][0] in ("<host>", "<native>", "<diff-return>"):
            return self._on_stub_body(uc, addr, 0, None)
        key = stubs[idx]
        if self._hle_mode == "record":
            return self._record_stub(uc, addr, key)
        return self._replay_stub(uc, key)

    def _stub_args(self, sp, key):
        entry = HLE.get(key)
        nargs = entry[1] if entry else 0
        return entry, nargs, (self.fast.read(sp + 4, 4 * nargs) if nargs else b"")

    def _record_stub(self, uc, addr, key):
        """Run an HLE handler as usual, with an undo log around it, and record what it did."""
        fast = self.fast
        sp = fast.get(UC_X86_REG_ESP)
        _, _, raw = self._stub_args(sp, key)
        args = struct.unpack("<%dI" % (len(raw) // 4), raw)
        ncoro = len(self.coros)
        log = self.undo_begin()
        try:
            self._on_stub_body(uc, addr, 0, None)
        finally:
            self.undo_end(log)
        # a coroutine (HLE call that calls back into guest code) finishes after this hook; it cannot be replayed
        unrep = len(self.coros) != ncoro or self.fatal is not None or self.exit_code is not None
        regs = {r: uc.reg_read(r) for r in SNAP_REGS}
        self._hle_rec.append(HleRec(key, sp, args, unrep, regs, log.writes()))

    def _replay_stub(self, uc, key):
        """Native run: the next recorded HLE call must be this one. Its effects are applied, the handler is not run."""
        fast = self.fast
        sp = fast.get(UC_X86_REG_ESP)
        entry, nargs, raw = self._stub_args(sp, key)
        frame_ret = struct.unpack("<I", fast.read(sp, 4))[0]
        args = struct.unpack("<%dI" % (len(raw) // 4), raw)
        cc = entry[2] if entry else "stdcall"
        name = "%s!%s" % key
        i = self._hle_cursor
        rec = self._hle_rec
        if i >= len(rec):
            return self._hle_diverge(uc, "HLE call %s(%s) with no reference record left" % (
                name, ", ".join("0x%x" % a for a in args)))
        r = rec[i]
        self._hle_cursor = i + 1
        if r.unrep:
            return self._hle_diverge(uc, "unreplayable HLE %s!%s" % r.key)
        if r.key != key or r.args != args or r.sp != sp:
            return self._hle_diverge(uc, "HLE call %s(%s) at esp 0x%x, reference record %s!%s(%s) at esp 0x%x" % (
                name, ", ".join("0x%x" % a for a in args), sp, r.key[0], r.key[1],
                ", ".join("0x%x" % a for a in r.args), r.sp))
        for rid, val in r.regs.items():
            uc.reg_write(rid, val)
        for start, data in write_runs(r.writes):
            self.wr(start, data)
        uc.reg_write(UC_X86_REG_ESP, (sp + 4 + (4 * nargs if cc == "stdcall" else 0)) & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_EIP, frame_ret)

    def _hle_diverge(self, uc, msg):
        """The native run stopped matching the reference run. Stop the emulator; the Native call that owns the
        replay sees the divergence and makes every later call_guest return at once."""
        self._hle_div = msg
        self.fatal = "diff divergence: " + msg
        uc.emu_stop()

    def _on_stub_body(self, uc, addr, size, user):
        idx = (addr - STUB_BASE) // STUB_STRIDE
        if idx == 0:
            uc.emu_stop()
            return
        if idx < len(self.stubs) and self.stubs[idx][0] == "<diff-return>":
            uc.emu_stop()                       # the reference run of a diffed function returned
            return
        if idx < len(self.stubs) and self.stubs[idx][0] == "<native>":
            # A lifted function was reached: stop, and let _drive run it between emu_start calls.
            if self._drive_depth == 0:
                self.fatal = "native slot reached outside the emulator driver (0x%x)" % addr
                uc.emu_stop()
                return
            self._native_pending = self.stubs[idx][1]
            uc.emu_stop()
            return
        # Coroutines whose HLE frame was abandoned by a guest unwind (catch continuation jumped to a
        # higher frame) are dead: drop them.
        fast = self.fast
        sp = fast.get(UC_X86_REG_ESP)
        while self.coros and self.coros[-1].sp0 < sp:
            self.coros.pop()
        if idx == 1:
            if not self.coros:
                self.fatal = "return to the HLE resume stub with no pending coroutine"
                uc.emu_stop()
                return
            self._advance(self.coros[-1], fast.get(UC_X86_REG_EAX))
            return
        key = self.stubs[idx]
        dll, name = key
        self.stub_counts[key] += 1
        entry = HLE.get(key)
        nargs = entry[1] if entry else 0
        frame = struct.unpack_from("<%dI" % (1 + nargs), fast.read(sp, 4 + 4 * nargs))   # return address, args
        ret = frame[0]
        if (dll, name) in self.stop_stubs:
            self.fatal = "reached %s!%s (called from %s)" % (dll, name, self.module_at(ret))
            uc.emu_stop()
            return
        if entry is None and dll == "MFC42.DLL" and self.mfc_lenient:
            # Bring-up only: log the call and return 0, popping the callee-cleaned bytes that
            # MFC42.DLL's own `ret N` says this ordinal takes.
            self.mfc_calls[(name, self.module_at(ret))] += 1
            n = self.mfc_ret_bytes().get(int(name[1:]), 0)
            self.apilog.append("MFC42!%s(...) [lenient, pops %d] from %s" % (name, n, self.module_at(ret)))
            fnv = self.mfc_retvals.get(int(name[1:]))
            uc.reg_write(UC_X86_REG_EAX, (fnv(self) if fnv else 0) & 0xFFFFFFFF)
            uc.reg_write(UC_X86_REG_ESP, sp + 4 + n)
            uc.reg_write(UC_X86_REG_EIP, ret)
            return
        if entry is None:
            self.fatal_args = [self.rd32(sp + 4 + 4 * i) for i in range(6)]   # kept for diagnosis
            self.fatal = "unimplemented import %s!%s (called from %s)" % (dll, name, self.module_at(ret))
            self.apilog.append(self.fatal)
            uc.emu_stop()
            return
        fn, nargs, cc = entry
        args = frame[1:]
        pop = 4 + (4 * nargs if cc == "stdcall" else 0)
        try:
            res = fn(self, *args)
        except Unimplemented as e:
            self.fatal = "%s!%s: %s (called from %s)" % (dll, name, e, self.module_at(ret))
            uc.emu_stop()
            return
        if hasattr(res, "send"):                      # generator: an HLE call that calls back into guest code
            co = Coro(res, sp, ret, pop, "%s!%s" % (dll, name))
            self.coros.append(co)
            self.apilog.append("%s(%s) [coroutine]" % (co.name, ", ".join("0x%x" % a for a in args)))
            self._advance(co, None)
            return
        if res is None:
            res = 0
        self._log_hle(dll, name, args, res)
        if self.exit_code is not None:
            uc.emu_stop()
            return
        fast.set(UC_X86_REG_EAX, res)
        fast.set(UC_X86_REG_ESP, sp + pop)
        fast.set(UC_X86_REG_EIP, ret)

    def _log_hle(self, dll, name, args, res):
        if name not in STRING_ARG_APIS and name != "GetProcAddress":
            self.apilog.append((dll, name, args, res))     # formatted when read (ApiLog.line)
            return
        shown = ", ".join("0x%x" % a for a in args)
        if name in STRING_ARG_APIS:
            try:
                shown += "  [%r]" % (self.wstr(args[0]) if name.endswith("W") else self.cstr(args[0], 200))
            except Exception:
                pass
        elif name == "GetProcAddress" and args[1] >= 0x10000:
            try:
                shown += "  [%r]" % self.cstr(args[1], 100)
            except Exception:
                pass
        self.apilog.append("%s!%s(%s) -> %s" % (dll, name, shown, hex(res & 0xFFFFFFFF)))

    def hle_direct(self, idx, cpu):
        """A call from lifted code to HLE stub idx, run without the emulator (runtime.c hle_direct): cpu is the lifted
        code's CPU (native.CPU), with the return address at [esp] and the arguments above it. Does what _on_stub_body
        does for an ordinary handler (one that returns a value): sets EAX and pops the frame. Returns HLE_DONE, or
        HLE_NEVER for a stub that is not in HLE_DIRECT (or has no handler), or HLE_DECLINE when this call must go
        through the stub after all (a coroutine, a stop stub, differential mode). An error (a fatal stop, process
        exit, any exception) is left for native.py to report. Each completed call adds to hle_direct_n/hle_direct_ns
        (the handler alone) and hle_direct_total_ns (this whole method)."""
        t0 = _now_ns()
        key = self.stubs[idx] if idx < len(self.stubs) else None
        if key not in HLE_DIRECT:
            return HLE_NEVER
        entry = HLE.get(key)
        if entry is None:
            return HLE_NEVER
        if self._hle_mode is not None or key in self.stop_stubs:
            return HLE_DECLINE
        fn, nargs, cc = entry
        sp = cpu.r[4]
        while self.coros and self.coros[-1].sp0 < sp:
            self.coros.pop()
        args = struct.unpack_from("<%dI" % nargs, self.fast.read(sp + 4, 4 * nargs)) if nargs else ()
        self._in_hook = True
        t1 = _now_ns()
        try:
            res = fn(self, *args)
        except Unimplemented as e:            # reported as through the stub: a fatal stop (native.py raises it)
            self.fatal = "%s!%s: %s (called from %s)" % (key[0], key[1], e, self.module_at(self.rd32(sp)))
            return HLE_HALT
        finally:
            self._in_hook = False
        t2 = _now_ns()
        if hasattr(res, "send"):                      # a coroutine: nothing has run yet; the stub will start it
            return HLE_DECLINE
        self.stub_counts[key] += 1
        self.hle_direct_n[key] += 1
        self.hle_direct_ns[key] += t2 - t1
        if res is None:
            res = 0
        self._log_hle(key[0], key[1], args, res)
        if self.exit_code is None and not self.fatal:
            cpu.r[0] = res & 0xFFFFFFFF
            cpu.r[4] = (sp + 4 + (4 * nargs if cc == "stdcall" else 0)) & 0xFFFFFFFF
        self.hle_direct_total_ns += _now_ns() - t0
        return HLE_DONE

    def hle_direct_profile(self, n=20, since=None):
        """The n direct-call handlers with the most handler time: [(key, calls, ns)]. since: an earlier
        (hle_direct_n, hle_direct_ns) copy to subtract."""
        cnt, ns = self.hle_direct_n, self.hle_direct_ns
        if since is not None:
            cnt, ns = cnt - since[0], ns - since[1]
        return sorted(((k, cnt[k], ns[k]) for k in cnt if cnt[k] > 0), key=lambda r: -r[2])[:n]

    def _advance(self, co, val):
        """Run an HLE coroutine until it either finishes or needs a guest function called."""
        uc = self.uc
        try:
            req = co.gen.send(val)
        except StopIteration as stop:
            if co in self.coros:
                self.coros.remove(co)
            res = stop.value
            if isinstance(res, ResumeAt):
                uc.reg_write(UC_X86_REG_EAX, res.eax & 0xFFFFFFFF)
                uc.reg_write(UC_X86_REG_ESP, res.esp)
                uc.reg_write(UC_X86_REG_EIP, res.eip)
            else:
                uc.reg_write(UC_X86_REG_EAX, (res or 0) & 0xFFFFFFFF)
                uc.reg_write(UC_X86_REG_ESP, co.sp0 + co.pop)
                uc.reg_write(UC_X86_REG_EIP, co.ret)
            return
        except Unimplemented as e:
            self.fatal = "%s: %s (called from %s)" % (co.name, e, self.module_at(co.ret))
            if co in self.coros:
                self.coros.remove(co)
            uc.emu_stop()
            return
        assert isinstance(req, GuestCall), req
        sp = co.sp0 - 0x100                          # below the HLE frame; callees live here
        for a in reversed(req.args):
            sp -= 4
            self.wr32(sp, a)
        sp -= 4
        self.wr32(sp, STUB_BASE + STUB_STRIDE)        # return into the resume stub
        co.call = req
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EIP, req.addr)

    def _on_unmapped(self, uc, access, address, size, value, user):
        eip = uc.reg_read(UC_X86_REG_EIP)
        self.fatal = "unmapped access %d at 0x%08x (size %d) from eip=0x%08x" % (
            access, address, size, eip)
        return False

    # ---------------------------------------------------------------- calling guest code
    def call(self, addr, *args, cc="stdcall", ecx=None, max_insns=0, timeout=0):
        """Call guest code at addr; returns eax. A budget (timeout in seconds of host time, or max_insns) that runs
        out sets budget_exhausted and leaves the guest where it is, for resume(). Prefer timeout: an instruction
        count makes Unicorn run a counting hook on every instruction, which is 5-20x slower."""
        uc = self.uc
        sp = uc.reg_read(UC_X86_REG_ESP)
        base_sp = sp
        # SEH records below the stack this call starts from belong to frames that are gone (a call stopped with
        # stop_at, like the CRT entry before AfxWinMain) and the callee's locals will overwrite them. Unlink them
        # so an exception nobody catches reaches the end of the chain instead of a handler read from garbage.
        # A dead record's next field may already be overwritten, so only trust it while the chain climbs the stack.
        head = self.rd32(TEB)
        while head != 0xFFFFFFFF and head < base_sp:
            nxt = self.rd32(head) if _in_stack(head) else 0xFFFFFFFF
            head = nxt if nxt == 0xFFFFFFFF or (_in_stack(nxt) and nxt > head) else 0xFFFFFFFF
        self.wr32(TEB, head)
        for a in reversed(args):
            sp -= 4
            self.wr32(sp, a)
        sp -= 4
        self.wr32(sp, STUB_BASE)  # return to host stub 0
        uc.reg_write(UC_X86_REG_ESP, sp)
        if ecx is not None:
            uc.reg_write(UC_X86_REG_ECX, ecx)
        self._call_base_sp = base_sp
        return self._run(addr, max_insns, timeout)

    def resume(self, max_insns=0, timeout=0):
        """Continue a call() that stopped because its budget ran out (self.budget_exhausted)."""
        assert self.budget_exhausted, "nothing to resume"
        return self._run(self.uc.reg_read(UC_X86_REG_EIP), max_insns, timeout)

    def _run(self, addr, max_insns, timeout=0):
        uc = self.uc
        self.fatal = None
        self.budget_exhausted = False
        # A timeout is a host timer that calls emu_stop(). (Unicorn's own `timeout` argument starts a watchdog
        # thread that wakes every 2 us, which keeps a second core busy for the whole run.)
        timer = threading.Timer(timeout, uc.emu_stop) if timeout else None
        if timer:
            timer.daemon = True
            timer.start()
        try:
            self._drive(addr, max_insns)
        finally:
            if timer:
                timer.cancel()
        eax = uc.reg_read(UC_X86_REG_EAX)
        if not self.fatal and uc.reg_read(UC_X86_REG_EIP) != STUB_BASE and self.exit_code is None:
            # Unicorn stops silently when `count` or `timeout` runs out. Leave the guest exactly where it is (registers
            # and stack) so the caller can resume(); do not pretend the call returned.
            self.budget_exhausted = True
            return eax
        uc.reg_write(UC_X86_REG_ESP, self._call_base_sp)
        return eax

    def _drive(self, addr, count=0, stop=STUB_BASE):
        """Run guest code from addr until it returns to the host slot (EIP == STUB_BASE), a fatal error, or the
        count budget. This is the only place that calls emu_start for guest code run on behalf of the host.
        A native (lifted) function reached by the guest stops emu_start with _native_pending set; the native call
        runs here, between emu_start calls, and the guest then continues at the return address it was given.
        Native code may call back into the guest (Native.call_guest), which re-enters this loop from Python: that
        is fine, but a hook must never reach here."""
        if self._in_hook:
            raise RuntimeError("emu_start requested from inside a Unicorn hook")
        if self.native is not None:
            self.native.check_undo()          # fast dispatch: native slots are refused under an undo log (native.py)
        uc = self.uc
        self._drive_depth += 1
        try:
            while True:
                try:
                    uc.emu_start(addr, stop, count=count)
                except UcError as e:
                    self._native_pending = None
                    if not self.fatal:
                        self.fatal = "UcError %s at eip=0x%08x" % (e, uc.reg_read(UC_X86_REG_EIP))
                    return
                va = self._native_pending
                if va is None:
                    return
                self._native_pending = None
                if self.fatal or self.exit_code is not None:
                    return
                addr = self._run_native_pending(va)
                if addr == STUB_BASE or self.fatal or self.exit_code is not None:
                    return
        finally:
            self._drive_depth -= 1
            # Fast native dispatch (emu/native.py): an error inside a nested native run is raised when the outermost
            # driver loop ends, after the hook has stopped the emulator.
            if self._drive_depth == 0 and self.native is not None and self.native.fast_error is not None:
                self.native._raise_fast()

    def _run_native_pending(self, va):
        """The one place a native call is dispatched from the emulator. The guest reached the native slot of va
        by `jmp`, with the return address at [esp]. Native.run_pending copies the registers into a CPU, runs the
        lifted function (which pops the return address itself) and copies the registers back. Returns the guest
        address to continue at."""
        if self.native is None:
            raise RuntimeError("native slot for 0x%x reached but no Native is bound to this Emu" % va)
        if self.native.diffing:
            return self.native.run_diff(va)      # sets EIP itself and returns the guest address to continue at
        sp = self.fast.get(UC_X86_REG_ESP)
        ret = self.rd32(sp)
        self.native.run_pending(va)
        self.uc.reg_write(UC_X86_REG_EIP, ret)
        return ret

    def native_slot(self, va):
        """A stub-range address whose hook means "run the native function of va" (M5). Cached per va."""
        cache = self.__dict__.setdefault("_native_slots", {})
        if va in cache:
            return cache[va]
        idx = len(self.stubs)
        if idx * STUB_STRIDE >= STUB_SIZE:
            raise MemoryError("stub region full")
        addr = STUB_BASE + idx * STUB_STRIDE
        self.stubs.append(("<native>", va))
        self.wr(addr, b"\xf4" * STUB_STRIDE)
        cache[va] = addr
        return addr

    def diff_return_slot(self):
        """The stub-range address differential mode returns a diffed function to (it stops the emulator there)."""
        if self._diff_slot_addr is None:
            idx = len(self.stubs)
            if idx * STUB_STRIDE >= STUB_SIZE:
                raise MemoryError("stub region full")
            self.stubs.append(("<diff-return>", None))
            self._diff_slot_addr = STUB_BASE + idx * STUB_STRIDE
            self.wr(self._diff_slot_addr, b"\xf4" * STUB_STRIDE)
        return self._diff_slot_addr

    def mfc_ret_bytes(self):
        """ordinal -> bytes popped by the callee, read from MFC42.DLL's `ret N` (not loaded, just parsed)."""
        if self.mfc_ret is not None:
            return self.mfc_ret
        import capstone
        path = os.path.join(self.game_dir, "MFC42.DLL")
        data = open(path, "rb").read()
        pe = pefile.PE(data=data)
        base = pe.OPTIONAL_HEADER.ImageBase
        secs = [(base + x.VirtualAddress, max(x.Misc_VirtualSize, x.SizeOfRawData), x.PointerToRawData,
                 x.SizeOfRawData) for x in pe.sections]

        def rdv(a, n):
            for lo, vs, raw, rs in secs:
                if lo <= a < lo + vs and a - lo + n <= rs:
                    return data[raw + a - lo: raw + a - lo + n]
            return None
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        out = {}
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            start = base + sym.address
            seen, todo, rets = set(), [start], set()
            budget = 400
            while todo and budget > 0:
                a = todo.pop()
                while a not in seen and budget > 0:
                    b = rdv(a, 16)
                    if not b:
                        break
                    ins = next(md.disasm(b, a), None)
                    if ins is None:
                        break
                    seen.add(a)
                    budget -= 1
                    if ins.mnemonic == "ret":
                        rets.add(ins.operands[0].imm if ins.operands else 0)
                        break
                    if ins.mnemonic.startswith("j") and ins.operands and ins.operands[0].type == 2:
                        todo.append(ins.operands[0].imm)
                        if ins.mnemonic == "jmp":
                            break
                    elif ins.mnemonic == "jmp":
                        break
                    a += ins.size
            if rets:
                out[sym.ordinal] = max(rets)
        self.mfc_ret = out
        return out

    def fp_return(self):
        """Read (and pop) the x87 return value ST0 as a Python float.

        Unicorn's ST0 register read only gives the mantissa, so run `fstp qword ptr [buf]` in the guest."""
        buf = SCRATCH + 0x100
        code = b"\xdd\x1d" + struct.pack("<I", buf) + b"\xf4"
        self.wr(SCRATCH, code)
        self.uc.emu_start(SCRATCH, SCRATCH + len(code) - 1)
        return struct.unpack("<d", self.rd(buf, 8))[0]

    def where(self):
        uc = self.uc
        regs = {n: uc.reg_read(r) for n, r in (
            ("eax", UC_X86_REG_EAX), ("ebx", UC_X86_REG_EBX), ("ecx", UC_X86_REG_ECX),
            ("edx", UC_X86_REG_EDX), ("esi", UC_X86_REG_ESI), ("edi", UC_X86_REG_EDI),
            ("ebp", UC_X86_REG_EBP), ("esp", UC_X86_REG_ESP), ("eip", UC_X86_REG_EIP))}
        return " ".join("%s=%08x" % kv for kv in regs.items())

    def module_at(self, va):
        for m in self.modules.values():
            if m.base <= va < m.base + m.size:
                return "%s+0x%x" % (m.name, va - m.base)
        return "0x%x" % va


# =============================================================================== HLE: kernel32
K = "KERNEL32.DLL"


def reg(name, nargs, cc="stdcall", dll=K):
    return hle(dll, name, nargs, cc)


@reg("GetLastError", 0)
def _(e): return e.last_error


@reg("SetLastError", 1)
def _(e, v): e.last_error = v


@reg("GetVersion", 0)
def _(e): return 0x0A280105


@reg("GetVersionExA", 1)
def _(e, p):
    e.wr(p + 4, struct.pack("<IIII", 5, 1, 2600, 2) + b"\0" * 128)
    return 1


DEFAULT_CMDLINE = '"C:\\MaxPayne\\MaxPayne.exe"'


@reg("GetCommandLineA", 0)
def _(e):
    cl = getattr(e, "command_line", DEFAULT_CMDLINE)
    if getattr(e, "_cmdline_a_for", None) != cl:
        e.cmdline = e.put_cstr(cl)
        e._cmdline_a_for = cl
    return e.cmdline


@reg("GetCommandLineW", 0)
def _(e):
    cl = getattr(e, "command_line", DEFAULT_CMDLINE)
    if getattr(e, "_cmdline_w_for", None) != cl:
        s = cl.encode("utf-16le") + b"\0\0"
        p = e.alloc(len(s))
        e.wr(p, s)
        e.cmdlinew = p
        e._cmdline_w_for = cl
    return e.cmdlinew


@reg("GetEnvironmentStrings", 0)
def _(e):
    p = e.alloc(8)
    return p


@reg("GetEnvironmentStringsW", 0)
def _(e): return e.alloc(8)


@reg("FreeEnvironmentStringsA", 1)
def _(e, p): return 1


@reg("FreeEnvironmentStringsW", 1)
def _(e, p): return 1


@reg("GetEnvironmentVariableA", 3)
def _(e, name, buf, size):
    e.last_error = 203
    return 0


@reg("SetEnvironmentVariableA", 2)
def _(e, a, b): return 1


@reg("SetEnvironmentVariableW", 2)
def _(e, a, b): return 1


@reg("GetStartupInfoA", 1)
def _(e, p):
    e.wr(p, struct.pack("<I", 68) + b"\0" * 64)


@reg("GetModuleHandleA", 1)
def _(e, name):
    if not name:
        return e.modules["maxpayne.exe"].base if "maxpayne.exe" in e.modules else 0x400000
    m = e.find_module(e.cstr(name))
    return m.base if m else 0


@reg("GetModuleFileNameA", 3)
def _(e, h, buf, size):
    nm = "MaxPayne.exe"
    for m in e.modules.values():
        if m.base == h:
            nm = m.name
    s = ("C:\\MaxPayne\\" + nm).encode()[:size - 1] + b"\0"
    e.wr(buf, s)
    return len(s) - 1


@reg("GetModuleFileNameW", 3)
def _(e, h, buf, size):
    nm = "MaxPayne.exe"
    for m in e.modules.values():
        if m.base == h:
            nm = m.name
    s = ("C:\\MaxPayne\\" + nm).encode("utf-16le")[:(size - 1) * 2] + b"\0\0"
    e.wr(buf, s)
    return len(s) // 2 - 1


FAKE_DLLS = {"d3d8.dll": 0x7E010000, "dinput.dll": 0x7E020000, "dsound.dll": 0x7E030000,
             "advapi32.dll": 0x7E040000, "shell32.dll": 0x7E050000}


@reg("LoadLibraryA", 1)
def load_library(e, name):
    """Return a loaded module's base; load a real DLL from the game folder on demand (map, relocate,
    resolve imports, run DllMain); hand out placeholder modules for system DLLs we replace ourselves."""
    raw = e.cstr(name)
    n = os.path.basename(raw.replace("\\", "/")).lower()
    m = e.find_module(n)
    if m:
        return m.base
    if n in FAKE_DLLS:
        # Placeholder module for system DLLs we will replace with our own HLE (Direct3D 8 in M3 etc.).
        # Its exports are stubs that stop with a clear message if anything actually calls them.
        return FAKE_DLLS[n]
    hp = host_read_path(e, raw)
    if n.endswith(".dll") and os.path.isfile(hp):
        mod = e.load_module(os.path.relpath(hp, e.game_dir))
        e.resolve_imports(mod)
        print("[LoadLibraryA] loaded %s at 0x%x (called from %s)" % (mod.name, mod.base, e.module_at(e.rd32(e.uc.reg_read(UC_X86_REG_ESP)))))
        # Load hooks (native.LiftLoader): the image is mapped, relocated and its imports resolved, DllMain has not run.
        # Only a first load gets here (find_module above returns for a loaded module).
        for cb in e.on_module_loaded:
            cb(mod)
        if mod.entry:
            ok = yield GuestCall(mod.entry, (mod.base, 1, 0), "stdcall")
            if not ok:
                print("[LoadLibraryA] DllMain of %s returned FALSE" % mod.name)
                e.last_error = 1114
                return 0
        return mod.base
    print("[LoadLibraryA] %r is not available -> NULL" % n)
    e.last_error = 126
    return 0


@reg("FreeLibrary", 1)
def _(e, h): return 1


# ---- shell folders (SHELL32, loaded with LoadLibrary: the exe asks for CSIDL_PERSONAL to put its saved games in
# "My Documents\Max Payne Savegames", maxpayne.exe+0x40fc98). Guest folders on C: outside the game live in the
# per-user data (see data_dir).
SHELL_FOLDERS = {0x05: "C:\\My Documents", 0x2E: "C:\\My Documents", 0x1A: "C:\\Application Data",
                 0x1C: "C:\\Local Settings\\Application Data", 0x10: "C:\\Desktop", 0x23: "C:\\All Users\\Application Data"}


@reg("SHGetSpecialFolderPathA", 4, dll="SHELL32.DLL")
def _(e, hwnd, buf, csidl, create):
    path = SHELL_FOLDERS.get(csidl & 0xFF)
    if path is None:
        return 0
    if create:
        os.makedirs(host_write_path(e, path), exist_ok=True)
    e.wr(buf, path.encode("latin1") + b"\0")
    return 1


@reg("GetProcAddress", 2)
def _(e, h, name):
    if name < 0x10000:
        for m in e.modules.values():
            if m.base == h:
                return m.ord_exports.get(name, 0)
        return 0
    n = e.cstr(name)
    for m in e.modules.values():
        if m.base == h:
            return m.exports.get(n, 0)
    for dll, b in FAKE_DLLS.items():
        if b == h:
            return e.stub_for(dll.upper(), n)
    return e.resolve_name(K, n)


@reg("DisableThreadLibraryCalls", 1)
def _(e, h): return 1


# ---- process / thread identity
@reg("GetCurrentProcess", 0)
def _(e): return 0xFFFFFFFF


@reg("GetCurrentThread", 0)
def _(e): return 0xFFFFFFFE


@reg("GetCurrentProcessId", 0)
def _(e): return 0x100


@reg("GetCurrentThreadId", 0)
def _(e): return 0x104


@reg("GetPriorityClass", 1)
def _(e, h): return 0x20


@reg("SetPriorityClass", 2)
def _(e, h, c): return 1


@reg("GetThreadPriority", 1)
def _(e, h): return 0


@reg("SetThreadPriority", 2)
def _(e, h, p): return 1


@reg("ExitProcess", 1)
def _(e, code): e.exit_code = code


@reg("TerminateProcess", 2)
def _(e, h, code): e.exit_code = code


@reg("SetErrorMode", 1)
def _(e, m): return 0


@reg("SetUnhandledExceptionFilter", 1)
def _(e, f): return 0


@reg("UnhandledExceptionFilter", 1)
def _(e, p): return 0


@reg("OutputDebugStringA", 1)
def _(e, s):
    print("[OutputDebugString]", e.cstr(s).rstrip())


@reg("GetComputerNameA", 2)
def _(e, buf, psize):
    e.wr(buf, b"MACBOOK\0")
    e.wr32(psize, 7)
    return 1


# Sleep returns at once (the emulated game runs slower than real time anyway); a layer that needs the time to pass,
# such as a playing movie (dshow.py), hooks it: SLEEP_HOOKS are called as hook(e, ms).
SLEEP_HOOKS = []


@reg("Sleep", 1)
def _(e, ms):
    for hook in SLEEP_HOOKS:
        hook(e, ms)
    return 0


# ---- heap / virtual memory
@reg("GetProcessHeap", 0)
def _(e): return 0x30000000


@reg("HeapCreate", 3)
def _(e, flags, init, mx): return 0x30000000 + 0x10000 * (len(e.heap) % 255 + 1)


@reg("HeapDestroy", 1)
def _(e, h): return 1


@reg("HeapAlloc", 3)
def _(e, h, flags, size):
    return e.alloc(size)


@reg("HeapFree", 3)
def _(e, h, flags, p):
    e.free(p)
    return 1


def _realloc(e, p, size):
    old, cap = (e.heap.get(p) if p else None) or (0, 0)
    if p and old and cap >= size:                         # fits in place: grow or shrink without moving
        e.heap.resize(p, max(size, 1))
        return p
    n = e.alloc(size)
    if p and old:
        e.wr(n, e.rd(p, min(old, size)))
        e.free(p)
    return n


@reg("HeapReAlloc", 4)
def _(e, h, flags, p, size):
    if flags & 0x10 and (e.heap.get(p) or (0, 0))[1] < size:   # HEAP_REALLOC_IN_PLACE_ONLY and it does not fit
        return 0
    return _realloc(e, p, size)


@reg("HeapSize", 3)
def _(e, h, flags, p): return (e.heap.get(p) or (0xFFFFFFFF,))[0]


@reg("HeapValidate", 3)
def _(e, h, flags, p): return 1


@reg("HeapCompact", 2)
def _(e, h, flags): return 0x10000


@reg("VirtualAlloc", 4)
def _(e, addr, size, typ, prot):
    return e.heap.reserve(size, True)


@reg("VirtualFree", 3)
def _(e, p, size, typ): return 1


@reg("GlobalMemoryStatus", 1)
def _(e, p):
    e.wr(p, struct.pack("<IIIIIIII", 32, 50, 0x40000000, 0x20000000, 0x80000000, 0x40000000,
                        0x7FFE0000, 0x70000000))


@reg("IsBadReadPtr", 2)
def _(e, p, n): return 0


@reg("IsBadWritePtr", 2)
def _(e, p, n): return 0


@reg("IsBadCodePtr", 1)
def _(e, p): return 0


# ---- TLS, critical sections, interlocked
@reg("TlsAlloc", 0)
def _(e):
    i = e.tls_next
    e.tls_next += 1
    e.tls[i] = 0
    return i


@reg("TlsFree", 1)
def _(e, i):
    e.tls.pop(i, None)
    return 1


@reg("TlsGetValue", 1)
def _(e, i):
    e.last_error = 0
    return e.tls.get(i, 0)


@reg("TlsSetValue", 2)
def _(e, i, v):
    e.tls[i] = v
    return 1


for _n in ("InitializeCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
           "DeleteCriticalSection"):
    reg(_n, 1)(lambda e, p: 0)


@reg("InterlockedIncrement", 1)
def _(e, p):
    v = (e.rd32(p) + 1) & 0xFFFFFFFF
    e.wr32(p, v)
    return v


@reg("InterlockedDecrement", 1)
def _(e, p):
    v = (e.rd32(p) - 1) & 0xFFFFFFFF
    e.wr32(p, v)
    return v


@reg("InterlockedExchange", 2)
def _(e, p, v):
    old = e.rd32(p)
    e.wr32(p, v)
    return old


@reg("CreateMutexA", 3)
def _(e, a, b, c): return e.new_handle("mutex")


@reg("ReleaseMutex", 1)
def _(e, h): return 1


@reg("CreateEventA", 4)
def _(e, a, b, c, d): return e.new_handle("event")


@reg("SetEvent", 1)
def _(e, h): return 1


@reg("WaitForSingleObject", 2)
def _(e, h, ms): return 0


def _new_handle(self, kind, obj=None):
    # A counter, not 0x200 + 4 * len(handles): after a CloseHandle that would hand out the number of a handle
    # still open and replace it (a music stream's file became another file mid-read).
    h = self.handle_next
    self.handle_next += 4
    self.handles[h] = (kind, obj)
    return h


Emu.new_handle = _new_handle


# ---- std handles / console (the CRT probes these at start-up)
@reg("GetStdHandle", 1)
def _(e, n): return {0xFFFFFFF6: 0x10, 0xFFFFFFF5: 0x11, 0xFFFFFFF4: 0x12}.get(n, 0xFFFFFFFF)


@reg("SetStdHandle", 2)
def _(e, n, h): return 1


@reg("GetFileType", 1)
def _(e, h): return 2 if h in (0x10, 0x11, 0x12) else 1


@reg("SetHandleCount", 1)
def _(e, n): return n


@reg("GetConsoleMode", 2)
def _(e, h, p):
    e.wr32(p, 3)
    return 1


@reg("SetConsoleMode", 2)
def _(e, h, m): return 1


@reg("SetConsoleCtrlHandler", 2)
def _(e, a, b): return 1


# ---- code pages / strings
@reg("GetACP", 0)
def _(e): return 1252


@reg("GetOEMCP", 0)
def _(e): return 437


@reg("IsValidCodePage", 1)
def _(e, cp): return 1


@reg("IsValidLocale", 2)
def _(e, a, b): return 1


@reg("GetUserDefaultLCID", 0)
def _(e): return 0x409


@reg("GetCPInfo", 2)
def _(e, cp, p):
    e.wr(p, struct.pack("<I", 1) + b"?\0" + b"\0" * 12)
    return 1


@reg("MultiByteToWideChar", 6)
def _(e, cp, flags, src, srclen, dst, dstlen):
    raw = e.rd(src, srclen) if srclen != 0xFFFFFFFF else (e.cstr(src).encode("latin1") + b"\0")
    out = raw.decode("latin1").encode("utf-16le")
    n = len(out) // 2
    if dstlen == 0:
        return n
    if n > dstlen:
        e.last_error = 122
        return 0
    e.wr(dst, out)
    return n


@reg("WideCharToMultiByte", 8)
def _(e, cp, flags, src, srclen, dst, dstlen, defchar, used):
    if srclen == 0xFFFFFFFF:
        text = e.wstr(src) + "\0"
    else:
        text = e.rd(src, srclen * 2).decode("utf-16le")
    out = text.encode("latin1", "replace")
    if dstlen == 0:
        return len(out)
    if len(out) > dstlen:
        e.last_error = 122
        return 0
    e.wr(dst, out)
    return len(out)


@reg("GetStringTypeA", 5)
def _(e, loc, typ, src, n, out):
    cnt = n if n != 0xFFFFFFFF else len(e.cstr(src)) + 1
    for i in range(cnt):
        c = e.rd(src + i, 1)[0]
        t = 0
        ch = chr(c)
        if ch.isupper():
            t |= 1
        if ch.islower():
            t |= 2
        if ch.isdigit():
            t |= 4
        if ch.isspace():
            t |= 8
        if ch in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~":
            t |= 0x10
        if c < 32 or c == 127:
            t |= 0x20
        if ch in "0123456789abcdefABCDEF":
            t |= 0x80
        if ch.isalpha():
            t |= 0x100
        e.wr(out + 2 * i, struct.pack("<H", t))
    return 1


@reg("GetStringTypeW", 4)
def _(e, typ, src, n, out):
    cnt = n if n != 0xFFFFFFFF else len(e.wstr(src)) + 1
    for i in range(cnt):
        c = struct.unpack("<H", e.rd(src + 2 * i, 2))[0]
        ch = chr(c)
        t = 0
        if ch.isupper():
            t |= 1
        if ch.islower():
            t |= 2
        if ch.isdigit():
            t |= 4
        if ch.isspace():
            t |= 8
        if ch.isalpha():
            t |= 0x100
        e.wr(out + 2 * i, struct.pack("<H", t))
    return 1


@reg("LCMapStringA", 6)
def _(e, loc, flags, src, srclen, dst, dstlen):
    s = e.rd(src, srclen) if srclen != 0xFFFFFFFF else e.cstr(src).encode("latin1") + b"\0"
    if flags & 0x200:
        s = s.upper()
    elif flags & 0x100:
        s = s.lower()
    if dstlen == 0:
        return len(s)
    e.wr(dst, s[:dstlen])
    return len(s)


@reg("LCMapStringW", 6)
def _(e, loc, flags, src, srclen, dst, dstlen):
    n = srclen if srclen != 0xFFFFFFFF else len(e.wstr(src)) + 1
    s = e.rd(src, n * 2)
    if dstlen == 0:
        return n
    e.wr(dst, s[:dstlen * 2])
    return n


@reg("CompareStringA", 6)
def _(e, loc, flags, a, na, b, nb):
    sa = e.rd(a, na) if na != 0xFFFFFFFF else e.cstr(a).encode("latin1")
    sb = e.rd(b, nb) if nb != 0xFFFFFFFF else e.cstr(b).encode("latin1")
    if flags & 1:
        sa, sb = sa.lower(), sb.lower()
    return 1 if sa < sb else (3 if sa > sb else 2)


@reg("CompareStringW", 6)
def _(e, loc, flags, a, na, b, nb):
    sa = e.rd(a, na * 2) if na != 0xFFFFFFFF else e.wstr(a).encode("utf-16le")
    sb = e.rd(b, nb * 2) if nb != 0xFFFFFFFF else e.wstr(b).encode("utf-16le")
    return 1 if sa < sb else (3 if sa > sb else 2)


@reg("GetLocaleInfoA", 4)
def _(e, loc, typ, buf, n):
    if n:
        e.wr(buf, b"1\0")
    return 2


@reg("GetLocaleInfoW", 4)
def _(e, loc, typ, buf, n):
    if n:
        e.wr(buf, b"1\0\0\0")
    return 2


@reg("EnumSystemLocalesA", 2)
def _(e, f, flags): return 1


# ---- time
def _now_filetime():
    return int((time.time() + 11644473600) * 10_000_000)


@reg("GetSystemTimeAsFileTime", 1)
def _(e, p): e.wr(p, struct.pack("<Q", _now_filetime()))


@reg("QueryPerformanceCounter", 1)
def _(e, p):
    e.wr(p, struct.pack("<Q", time.perf_counter_ns() // 1000))
    return 1


@reg("QueryPerformanceFrequency", 1)
def _(e, p):
    e.wr(p, struct.pack("<Q", 1_000_000))
    return 1


@reg("timeGetTime", 0, dll="WINMM.DLL")
def _(e): return (time.perf_counter_ns() // 1_000_000) & 0xFFFFFFFF


def _systemtime(t, ms=0):
    tm = time.gmtime(t)
    return struct.pack("<8H", tm.tm_year, tm.tm_mon, (tm.tm_wday + 1) % 7, tm.tm_mday,
                       tm.tm_hour, tm.tm_min, tm.tm_sec, ms)


@reg("GetSystemTime", 1)
def _(e, p): e.wr(p, _systemtime(time.time()))


@reg("GetLocalTime", 1)
def _(e, p): e.wr(p, _systemtime(time.time()))


@reg("GetTimeZoneInformation", 1)
def _(e, p):
    e.wr(p, b"\0" * 172)
    return 0


# ---- exceptions (not supported yet: bring-up stops with a clear message)
def describe_cxx_exception(e, args, n):
    """Decode an MSVC C++ exception (code 0xe06d7363): thrown object, its type name, and the thrower chain."""
    try:
        obj, ti = e.rd32(args + 4), e.rd32(args + 8)
        cta = e.rd32(ti + 12)
        names = []
        for i in range(e.rd32(cta)):
            ct = e.rd32(cta + 4 + 4 * i)
            td = e.rd32(ct + 4)
            names.append(e.cstr(td + 8))
        # call chain via the EBP links of the guest frames
        ebp = e.uc.reg_read(UC_X86_REG_EBP)
        chain = []
        for _ in range(8):
            if not (STACK_TOP - STACK_SIZE < ebp < STACK_TOP):
                break
            chain.append(e.module_at(e.rd32(ebp + 4)))
            ebp = e.rd32(ebp)
        strs = []
        for off in range(0, 0x80, 4):
            v = e.rd32(obj + off)
            for cand in (v, ):
                try:
                    t = e.cstr(cand, 120)
                    if len(t) >= 6 and all(32 <= ord(c) < 127 for c in t):
                        strs.append("+0x%x: %r" % (off, t))
                except Exception:
                    pass
        return "C++ exception object=0x%x types=%s\n   string fields: %s\n   call chain: %s" % (
            obj, names[:3], "; ".join(strs[:4]) or "-", " <- ".join(chain))
    except Exception as ex:
        return "C++ exception (could not decode: %s)" % ex


# ---- structured exception handling. The real MSVCRT frame handlers (__CxxFrameHandler, _except_handler3)
# run as guest code; this is the OS half they expect: walk the fs:[0] registration chain, call each
# handler, and implement RtlUnwind. Both are generators so they can call guest handlers (see Coro).
EH_NONCONTINUABLE, EH_UNWINDING, EH_EXIT_UNWIND = 0x1, 0x2, 0x4
STATUS_UNWIND = 0xC0000027
CONTEXT_SIZE = 716


def _in_stack(addr):
    return STACK_TOP - STACK_SIZE <= addr < STACK_TOP


def _capture_context(e, eip, esp, eax=None):
    """Build an x86 CONTEXT (716 bytes) from the current registers, with Eip/Esp as the caller will see them."""
    uc = e.uc
    ctx = e.alloc(CONTEXT_SIZE)
    buf = bytearray(CONTEXT_SIZE)

    def put(off, v):
        struct.pack_into("<I", buf, off, v & 0xFFFFFFFF)
    put(0, 0x1003F)                                  # CONTEXT_FULL | floating point | i386
    put(28, uc.reg_read(UC_X86_REG_FPCW))
    put(140, 0)
    put(156, uc.reg_read(UC_X86_REG_EDI)); put(160, uc.reg_read(UC_X86_REG_ESI))
    put(164, uc.reg_read(UC_X86_REG_EBX)); put(168, uc.reg_read(UC_X86_REG_EDX))
    put(172, uc.reg_read(UC_X86_REG_ECX))
    put(176, uc.reg_read(UC_X86_REG_EAX) if eax is None else eax)
    put(180, uc.reg_read(UC_X86_REG_EBP)); put(184, eip)
    put(188, 0x1B); put(192, 0x202); put(196, esp); put(200, 0x23)
    e.wr(ctx, bytes(buf))
    return ctx


def _load_context(e, ctx):
    """Resume guest execution from a CONTEXT (used when a handler returns ExceptionContinueExecution)."""
    uc = e.uc
    for off, reg in ((156, UC_X86_REG_EDI), (160, UC_X86_REG_ESI), (164, UC_X86_REG_EBX),
                     (168, UC_X86_REG_EDX), (172, UC_X86_REG_ECX), (180, UC_X86_REG_EBP)):
        uc.reg_write(reg, e.rd32(ctx + off))
    return ResumeAt(e.rd32(ctx + 184), e.rd32(ctx + 196), e.rd32(ctx + 176))


@reg("ExceptionNestedHandler", 4, cc="cdecl", dll="NTDLL.DLL")
def _(e, rec, frame, ctx, dc):
    """Handler of the dispatcher's own registration record: during an unwind it just lets the search go on;
    anywhere else it would mean an exception was raised inside a handler (nested exception)."""
    return 1 if e.rd32(rec + 4) & (EH_UNWINDING | EH_EXIT_UNWIND) else 2


def _push_dispatcher_frame(e, sp0):
    """While a handler runs, real Windows keeps a registration record of its own at the head of fs:[0].
    MSVC's _UnwindNestedFrames saves fs:[0] expecting exactly that record, so we must provide one."""
    reg = sp0 - 0x20
    e.wr32(reg, e.rd32(TEB))
    e.wr32(reg + 4, e.stub_for("NTDLL.DLL", "ExceptionNestedHandler"))
    e.wr32(TEB, reg)
    return reg


@reg("RaiseException", 4)
def raise_exception(e, code, flags, nargs, args):
    uc = e.uc
    sp0 = uc.reg_read(UC_X86_REG_ESP)
    ret = e.rd32(sp0)
    nargs = min(nargs, 15)
    rec = e.alloc(80)
    e.wr(rec, struct.pack("<IIIII", code, flags, 0, ret, nargs))
    if nargs and args:
        e.wr(rec + 20, e.rd(args, 4 * nargs))
    ctx = _capture_context(e, ret, sp0 + 4 + 16)       # as seen by the caller after RaiseException returns
    dc = e.alloc(32)
    frame = e.rd32(TEB)
    guard = 0
    chain, f = [], frame
    for _ in range(10):
        if f == 0xFFFFFFFF or not _in_stack(f):
            break
        chain.append("0x%x->0x%x[%s]" % (f, e.rd32(f), e.module_at(e.rd32(f + 4))))
        f = e.rd32(f)
    e.apilog.append("SEH raise code=0x%x chain: %s" % (code, " ".join(chain)))
    if code == 0xE06D7363:
        e.apilog.append("SEH   thrown: " + describe_cxx_exception(e, args, nargs).replace("\n", " | ")[:400])
    while frame != 0xFFFFFFFF and _in_stack(frame) and guard < 256:
        guard += 1
        handler = e.rd32(frame + 4)
        reg_ = _push_dispatcher_frame(e, sp0)
        disp = (yield GuestCall(handler, (rec, frame, ctx, dc), "cdecl")) & 0xFFFFFFFF
        e.wr32(TEB, e.rd32(reg_))                       # handler returned: the dispatcher's record is popped
        e.apilog.append("SEH pass1 frame=0x%x handler=%s -> disposition %d" % (frame, e.module_at(handler), disp))
        if disp == 0:                                   # ExceptionContinueExecution
            if flags & EH_NONCONTINUABLE:
                raise Unimplemented("handler continued a non-continuable exception 0x%x" % code)
            return _load_context(e, ctx)
        if disp == 1:                                   # ExceptionContinueSearch
            frame = e.rd32(frame)
            continue
        raise Unimplemented("exception handler 0x%x returned disposition %d (nested/collided not supported)"
                            % (handler, disp))
    what = describe_cxx_exception(e, args, nargs) if code == 0xE06D7363 else ""
    raise Unimplemented("unhandled exception 0x%x raised at %s %s" % (code, e.module_at(ret), what))


@reg("RtlUnwind", 4)
def rtl_unwind(e, target, target_ip, record, retval):
    uc = e.uc
    sp0 = uc.reg_read(UC_X86_REG_ESP)
    ret = e.rd32(sp0)
    if not record:
        record = e.alloc(80)
        e.wr(record, struct.pack("<IIIII", STATUS_UNWIND, 0, 0, ret, 0))
    saved_flags = e.rd32(record + 4)
    e.wr32(record + 4, saved_flags | EH_UNWINDING | (EH_EXIT_UNWIND if not target else 0))
    ctx = _capture_context(e, ret, sp0 + 4 + 16, eax=retval)
    dc = e.alloc(32)
    frame = e.rd32(TEB)
    guard = 0
    while frame != 0xFFFFFFFF and frame != target and _in_stack(frame) and guard < 256:
        guard += 1
        handler = e.rd32(frame + 4)
        _push_dispatcher_frame(e, sp0)
        yield GuestCall(handler, (record, frame, ctx, dc), "cdecl")
        nxt = e.rd32(frame)
        e.wr32(TEB, nxt)                                # the frame is gone once its handler has run
        frame = nxt
    e.wr32(record + 4, saved_flags)
    # RtlUnwind continues at TargetIp (normally the instruction after the call) with EAX=ReturnValue
    return ResumeAt(target_ip or ret, sp0 + 4 + 16, retval)





# =============================================================================== HLE: files and directories
import fnmatch
import shutil

GENERIC_WRITE = 0x40000000
INVALID_HANDLE = 0xFFFFFFFF


# Per-user data, kept outside the game folder (which stays read-only):
#   <data>/registry.json   the registry (HKCU etc.), written through on every change
#   <data>/game/           copy-on-write overlay for files the game writes into its own folder (C:\MaxPayne)
#   <data>/C/...           the rest of the guest's C: drive, e.g. C:\My Documents\Max Payne Savegames
# <data> is e.data_dir, else $MAXPAYNE_DATA, else ~/Library/Application Support/Max Payne Recomp.
DEFAULT_DATA_DIR = os.path.expanduser("~/Library/Application Support/Max Payne Recomp")


def data_dir(e):
    d = getattr(e, "data_dir", None) or os.environ.get("MAXPAYNE_DATA") or DEFAULT_DATA_DIR
    e.data_dir = d
    os.makedirs(d, exist_ok=True)
    return d


def _overlay(e):
    d = os.path.join(data_dir(e), "game")
    os.makedirs(d, exist_ok=True)
    return d


def _ci_join(root, parts):
    """Join parts under root, matching existing names case-insensitively (Windows paths on a host file system)."""
    cur = root
    for part in parts:
        try:
            hit = next((n for n in os.listdir(cur) if n.lower() == part.lower()), None)
        except OSError:
            hit = None
        cur = os.path.join(cur, hit or part)
    return cur


def _locate(e, guest):
    """("game", parts relative to C:\\MaxPayne) or ("drive", [drive letter] + parts) for a guest path."""
    g = _guest_abs(e, guest).replace("/", "\\")
    drive = g[0].upper() if len(g) > 1 and g[1] == ":" else "C"
    parts = [x for x in g[2:].split("\\") if x and x != "."]
    out = []
    for x in parts:                                       # resolve .. textually, as Windows does
        if x == "..":
            if out:
                out.pop()
        else:
            out.append(x)
    if drive == "C" and out and out[0].lower() == "maxpayne":
        return "game", out[1:]
    return "drive", [drive] + out


def _guest_abs(e, guest):
    g = guest.replace("/", "\\")
    if len(g) > 1 and g[1] == ":":
        return g
    if g.startswith("\\"):                               # rooted: on the current drive (C:)
        return "C:" + g
    base = getattr(e, "cwd", "C:\\MaxPayne")
    return base.rstrip("\\") + "\\" + g


def host_read_path(e, guest):
    """Existing file or directory for reading. In the game folder the write overlay wins for paths it has, then
    the game dir (the root itself is always the game dir); elsewhere on the drive, the per-user data."""
    kind, parts = _locate(e, guest)
    if kind == "drive":
        return _ci_join(data_dir(e), parts)
    if parts:
        ov = _ci_join(_overlay(e), parts)
        if os.path.exists(ov):
            return ov
    return e.host_path("C:\\MaxPayne\\" + "\\".join(parts))


def host_write_path(e, guest):
    kind, parts = _locate(e, guest)
    p = _ci_join(data_dir(e) if kind == "drive" else _overlay(e), parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    return p


def _w(fn):
    """Wide-string variant helper: decode a wide pointer then call the narrow logic."""
    return fn


@reg("GetCurrentDirectoryA", 2)
def _(e, size, buf):
    cwd = getattr(e, "cwd", "C:\\MaxPayne")
    if size < len(cwd) + 1:
        return len(cwd) + 1
    e.wr(buf, cwd.encode() + b"\0")
    return len(cwd)


@reg("GetCurrentDirectoryW", 2)
def _(e, size, buf):
    cwd = getattr(e, "cwd", "C:\\MaxPayne")
    if size < len(cwd) + 1:
        return len(cwd) + 1
    e.wr(buf, cwd.encode("utf-16le") + b"\0\0")
    return len(cwd)


@reg("SetCurrentDirectoryA", 1)
def _(e, p):
    e.cwd = _guest_abs(e, e.cstr(p)).rstrip("\\")
    return 1


@reg("SetCurrentDirectoryW", 1)
def _(e, p):
    e.cwd = _guest_abs(e, e.wstr(p)).rstrip("\\")
    return 1


@reg("GetFullPathNameA", 4)
def _(e, name, size, buf, pfile):
    full = _guest_abs(e, e.cstr(name))
    if size < len(full) + 1:
        return len(full) + 1
    e.wr(buf, full.encode() + b"\0")
    if pfile:
        e.wr32(pfile, buf + full.rfind("\\") + 1)
    return len(full)


@reg("GetFullPathNameW", 4)
def _(e, name, size, buf, pfile):
    full = _guest_abs(e, e.wstr(name))
    if size < len(full) + 1:
        return len(full) + 1
    e.wr(buf, full.encode("utf-16le") + b"\0\0")
    if pfile:
        e.wr32(pfile, buf + 2 * (full.rfind("\\") + 1))
    return len(full)


@reg("GetShortPathNameA", 3)
def _(e, name, buf, size):
    s = e.cstr(name)
    if size < len(s) + 1:
        return len(s) + 1
    e.wr(buf, s.encode() + b"\0")
    return len(s)


def _attrs(path):
    if os.path.isdir(path):
        return 0x10
    if os.path.exists(path):
        return 0x20
    return INVALID_HANDLE


@reg("GetFileAttributesA", 1)
def _(e, name):
    a = _attrs(host_read_path(e, e.cstr(name)))
    if a == INVALID_HANDLE:
        e.last_error = 2
    return a


@reg("GetFileAttributesW", 1)
def _(e, name):
    a = _attrs(host_read_path(e, e.wstr(name)))
    if a == INVALID_HANDLE:
        e.last_error = 2
    return a


@reg("SetFileAttributesA", 2)
def _(e, n, a): return 1


@reg("SetFileAttributesW", 2)
def _(e, n, a): return 1


def _open_file(e, guest, access, disp):
    writing = bool(access & GENERIC_WRITE) or disp in (1, 2, 4, 5)
    if writing:
        rp = host_read_path(e, guest)
        wp = host_write_path(e, guest)
        exists = os.path.exists(rp)
        if disp == 1 and exists:
            e.last_error = 80
            return INVALID_HANDLE
        if disp == 3 and not exists:
            e.last_error = 2
            return INVALID_HANDLE
        if exists and rp != wp and disp != 2 and disp != 5:
            shutil.copyfile(rp, wp)          # copy-on-write into the overlay
        mode = "w+b" if disp in (2, 5) or not os.path.exists(wp) else "r+b"
        f = open(wp, mode)
    else:
        rp = host_read_path(e, guest)
        if not os.path.isfile(rp):
            e.last_error = 2
            return INVALID_HANDLE
        f = open(rp, "rb")
    e.last_error = 0
    return e.new_handle("file", f)


@reg("CreateFileA", 7)
def _(e, name, access, share, sec, disp, flags, tmpl):
    return _open_file(e, e.cstr(name), access, disp)


@reg("CreateFileW", 7)
def _(e, name, access, share, sec, disp, flags, tmpl):
    return _open_file(e, e.wstr(name), access, disp)


def _file(e, h):
    k = e.handles.get(h)
    return k[1] if k and k[0] == "file" else None


@reg("ReadFile", 5)
def _(e, h, buf, n, pread, ovl):
    f = _file(e, h)
    if f is None:
        e.last_error = 6
        return 0
    data = f.read(n)
    e.wr(buf, data)
    if pread:
        e.wr32(pread, len(data))
    return 1


@reg("WriteFile", 5)
def _(e, h, buf, n, pwritten, ovl):
    data = e.rd(buf, n)
    if h in (0x11, 0x12):
        sys.stdout.write(data.decode("latin1"))
    else:
        f = _file(e, h)
        if f is None:
            e.last_error = 6
            return 0
        f.write(data)
    if pwritten:
        e.wr32(pwritten, n)
    return 1


@reg("SetFilePointer", 4)
def _(e, h, lo, phi, method):
    f = _file(e, h)
    if f is None:
        return INVALID_HANDLE
    off = lo - (1 << 32) if lo & 0x80000000 else lo
    f.seek(off, method)
    return f.tell() & 0xFFFFFFFF


@reg("GetFileSize", 2)
def _(e, h, phigh):
    f = _file(e, h)
    if f is None:
        return INVALID_HANDLE
    cur = f.tell()
    f.seek(0, 2)
    size = f.tell()
    f.seek(cur)
    if phigh:
        e.wr32(phigh, size >> 32)
    return size & 0xFFFFFFFF


@reg("GetFileTime", 4)
def _(e, h, c, a, w):
    t = struct.pack("<Q", _now_filetime())
    for p in (c, a, w):
        if p:
            e.wr(p, t)
    return 1


@reg("SetFileTime", 4)
def _(e, h, c, a, w): return 1


@reg("SetEndOfFile", 1)
def _(e, h):
    f = _file(e, h)
    if f:
        f.truncate()
    return 1


@reg("FlushFileBuffers", 1)
def _(e, h): return 1


@reg("GetFileInformationByHandle", 2)
def _(e, h, p):
    f = _file(e, h)
    if f is None:
        return 0
    cur = f.tell()
    f.seek(0, 2)
    size = f.tell()
    f.seek(cur)
    e.wr(p, struct.pack("<I", 0x20) + b"\0" * 24 + struct.pack("<IIIII", 0, size, 1, 0, 0)[:20] + b"\0" * 4)
    return 1


@reg("LockFile", 5)
def _(e, h, a, b, c, d): return 1


@reg("UnlockFile", 5)
def _(e, h, a, b, c, d): return 1


@reg("CloseHandle", 1)
def _(e, h):
    k = e.handles.pop(h, None)
    if k and k[0] == "file":
        try:
            k[1].close()
        except Exception:
            pass
    return 1


@reg("DuplicateHandle", 7)
def _(e, a, b, c, d, f, g, h): raise Unimplemented("DuplicateHandle")


@reg("CreateFileMappingA", 6)
def _(e, h, sec, prot, hi, lo, name):
    f = _file(e, h)
    if f is None:
        return 0
    return e.new_handle("mapping", f)


@reg("MapViewOfFile", 5)
def _(e, h, access, hi, lo, n):
    k = e.handles.get(h)
    if not k or k[0] != "mapping":
        return 0
    f = k[1]
    cur = f.tell()
    f.seek(0, 2)
    size = f.tell()
    f.seek(lo)
    data = f.read(n or (size - lo))
    f.seek(cur)
    p = e.heap.reserve(len(data), False)
    e.wr(p, data)
    return p


@reg("UnmapViewOfFile", 1)
def _(e, p): return 1


# ---- directory enumeration
def _filetime_of(path):
    try:
        return int((os.path.getmtime(path) + 11644473600) * 10_000_000)
    except OSError:
        return 0


def _find_entries(e, pattern_guest):
    parts = _guest_abs(e, pattern_guest)
    d, _, pat = parts.rpartition("\\")
    guest_dir = d if d else "C:\\MaxPayne"
    kind, parts = _locate(e, guest_dir)
    if kind == "drive":
        game_dir = ov_dir = _ci_join(data_dir(e), parts)
    else:
        game_dir = e.host_path("C:\\MaxPayne\\" + "\\".join(parts))
        ov_dir = _ci_join(_overlay(e), parts)
    listing = {}
    for base in (game_dir, ov_dir):                      # overlay entries shadow game files of the same name
        try:
            for n in os.listdir(base):
                listing[n.lower()] = (n, os.path.join(base, n))
        except OSError:
            pass
    if not listing and not os.path.isdir(game_dir) and not os.path.isdir(ov_dir):
        return []
    out = []
    for n in [".", ".."] + sorted(v[0] for v in listing.values()):
        if fnmatch.fnmatch(n.lower(), pat.lower().replace("*.*", "*")):
            out.append((n, listing[n.lower()][1] if n.lower() in listing else game_dir))
    return out


def _fill_find(e, p, ent, wide):
    name, full = ent
    isdir = os.path.isdir(full)
    size = 0 if isdir else os.path.getsize(full)
    ft = struct.pack("<Q", _filetime_of(full))
    buf = struct.pack("<I", 0x10 if isdir else 0x20) + ft * 3 + struct.pack("<IIII", size >> 32,
                                                                          size & 0xFFFFFFFF, 0, 0)
    if wide:
        nm = name.encode("utf-16le")[:518] + b"\0\0"
        buf += nm.ljust(520, b"\0") + b"\0" * 28
    else:
        buf += name.encode("latin1")[:259].ljust(260, b"\0") + b"\0" * 14
    e.wr(p, buf)


def _find_first(e, pattern, p, wide):
    ents = _find_entries(e, pattern)
    if not ents:
        e.last_error = 2
        return INVALID_HANDLE
    h = e.new_handle("find", [ents, 1, wide])
    _fill_find(e, p, ents[0], wide)
    return h


def _find_next(e, h, p):
    k = e.handles.get(h)
    if not k or k[0] != "find":
        return 0
    ents, i, wide = k[1]
    if i >= len(ents):
        e.last_error = 18
        return 0
    _fill_find(e, p, ents[i], wide)
    k[1][1] = i + 1
    return 1


@reg("FindFirstFileA", 2)
def _(e, pat, p): return _find_first(e, e.cstr(pat), p, False)


@reg("FindFirstFileW", 2)
def _(e, pat, p): return _find_first(e, e.wstr(pat), p, True)


@reg("FindNextFileA", 2)
def _(e, h, p): return _find_next(e, h, p)


@reg("FindNextFileW", 2)
def _(e, h, p): return _find_next(e, h, p)


@reg("FindClose", 1)
def _(e, h):
    e.handles.pop(h, None)
    return 1


@reg("CreateDirectoryA", 2)
def _(e, p, sec):
    os.makedirs(host_write_path(e, e.cstr(p)), exist_ok=True)
    return 1


@reg("CreateDirectoryW", 2)
def _(e, p, sec):
    os.makedirs(host_write_path(e, e.wstr(p)), exist_ok=True)
    return 1


@reg("RemoveDirectoryA", 1)
def _(e, p): return 1


@reg("RemoveDirectoryW", 1)
def _(e, p): return 1


@reg("DeleteFileA", 1)
def _(e, p):
    try:
        os.remove(host_write_path(e, e.cstr(p)))
    except OSError:
        pass
    return 1


@reg("DeleteFileW", 1)
def _(e, p):
    try:
        os.remove(host_write_path(e, e.wstr(p)))
    except OSError:
        pass
    return 1


@reg("CopyFileA", 3)
def _(e, a, b, fail_if_exists):
    src = host_read_path(e, e.cstr(a))
    if not os.path.isfile(src):
        e.last_error = 2
        return 0
    shutil.copyfile(src, host_write_path(e, e.cstr(b)))
    return 1


@reg("GetDiskFreeSpaceA", 5)
def _(e, root, spc, bps, free, total):
    for p, v in ((spc, 8), (bps, 512), (free, 1 << 20), (total, 2 << 20)):
        if p:
            e.wr32(p, v)
    return 1


@reg("GetDriveTypeA", 1)
def _(e, p): return 3


@reg("GetDriveTypeW", 1)
def _(e, p): return 3


@reg("GetLogicalDrives", 0)
def _(e): return 0x4


@reg("FileTimeToSystemTime", 2)
def _(e, pft, pst):
    ft = struct.unpack("<Q", e.rd(pft, 8))[0]
    e.wr(pst, _systemtime(ft / 10_000_000 - 11644473600))
    return 1


@reg("FileTimeToLocalFileTime", 2)
def _(e, a, b):
    e.wr(b, e.rd(a, 8))
    return 1


@reg("LocalFileTimeToFileTime", 2)
def _(e, a, b):
    e.wr(b, e.rd(a, 8))
    return 1


@reg("SystemTimeToFileTime", 2)
def _(e, a, b):
    y, mo, dow, d, h, mi, sec, ms = struct.unpack("<8H", e.rd(a, 16))
    import calendar
    t = calendar.timegm((y, mo, d, h, mi, sec))
    e.wr(b, struct.pack("<Q", int((t + 11644473600) * 10_000_000)))
    return 1


@reg("SetLocalTime", 1)
def _(e, p): return 1


@reg("Beep", 2)
def _(e, f, d): return 1


# =============================================================================== HLE: MFC42 (by ordinal)
# MFC42 here exports ordinals only. #823/#825 are the engine DLLs' only MFC imports; they are the
# global operator new/delete (cdecl), per the M1 census.
@reg("#823", 1, cc="cdecl", dll="MFC42.DLL")
def _(e, size): return e.alloc(size)


@reg("#825", 1, cc="cdecl", dll="MFC42.DLL")
def _(e, p):
    e.free(p)


# =============================================================================== HLE: kernel32 batch for MFC42
# Local*/Global* memory: fixed memory, handle == pointer.
def _lalloc(e, flags, size): return e.alloc(size)


def _lrealloc(e, p, size, flags): return _realloc(e, p, size)


for _pfx in ("Local", "Global"):
    reg(_pfx + "Alloc", 2)(_lalloc)
    reg(_pfx + "ReAlloc", 3)(_lrealloc)
    reg(_pfx + "Free", 1)(lambda e, p: (e.free(p), 0)[1])
    reg(_pfx + "Lock", 1)(lambda e, p: p)
    reg(_pfx + "Unlock", 1)(lambda e, p: 0)
    reg(_pfx + "Size", 1)(lambda e, p: (e.heap.get(p) or (0,))[0])
reg("GlobalHandle", 1)(lambda e, p: p)
reg("GlobalFlags", 1)(lambda e, p: 0)


@reg("lstrlenA", 1)
def _(e, p): return len(e.cstr(p)) if p else 0


@reg("lstrlenW", 1)
def _(e, p): return len(e.wstr(p)) if p else 0


@reg("lstrcpyA", 2)
def _(e, d, s_):
    e.wr(d, e.cstr(s_).encode("latin1") + b"\0")
    return d


@reg("lstrcpyW", 2)
def _(e, d, s_):
    e.wr(d, e.wstr(s_).encode("utf-16le") + b"\0\0")
    return d


@reg("lstrcpynA", 3)
def _(e, d, s_, n):
    if n:
        e.wr(d, e.cstr(s_).encode("latin1")[:n - 1] + b"\0")
    return d


@reg("lstrcatA", 2)
def _(e, d, s_):
    e.wr(d + len(e.cstr(d)), e.cstr(s_).encode("latin1") + b"\0")
    return d


def _cmp(a, b): return (a > b) - (a < b)


@reg("lstrcmpA", 2)
def _(e, a, b): return _cmp(e.cstr(a), e.cstr(b)) & 0xFFFFFFFF


@reg("lstrcmpiA", 2)
def _(e, a, b): return _cmp(e.cstr(a).lower(), e.cstr(b).lower()) & 0xFFFFFFFF


reg("IsBadStringPtrA", 2)(lambda e, p, n: 0)
reg("IsBadStringPtrW", 2)(lambda e, p, n: 0)
reg("IsDBCSLeadByte", 1)(lambda e, c: 0)
reg("GetThreadLocale", 0)(lambda e: 0x409)
reg("GetProcessVersion", 1)(lambda e, pid: 0x00050001)
reg("GetTickCount", 0)(lambda e: (time.perf_counter_ns() // 1_000_000) & 0xFFFFFFFF)


@reg("MulDiv", 3)
def _(e, a, b, c):
    def sg(x): return x - (1 << 32) if x & 0x80000000 else x
    a, b, c = sg(a), sg(b), sg(c)
    if c == 0:
        return 0xFFFFFFFF
    q = (a * b + (abs(c) // 2) * (1 if (a * b >= 0) == (c > 0) else -1)) // c if False else round(a * b / c)
    return q & 0xFFFFFFFF


reg("GetStringTypeExA", 5)(lambda e, loc, typ, src, n, out: HLE[(K, "GetStringTypeA")][0](e, loc, typ, src, n, out))


@reg("GetSystemDirectoryA", 2)
def _(e, buf, size):
    s_ = b"C:\\WINDOWS\\SYSTEM32"
    if size > len(s_):
        e.wr(buf, s_ + b"\0")
    return len(s_)


@reg("GetTempPathA", 2)
def _(e, size, buf):
    s_ = b"C:\\TEMP\\"
    if size > len(s_):
        e.wr(buf, s_ + b"\0")
    return len(s_)


@reg("GetTempFileNameA", 4)
def _(e, path, prefix, unique, out):
    e.wr(out, (e.cstr(path) + e.cstr(prefix) + "1.tmp").encode() + b"\0")
    return 1


reg("GetVolumeInformationA", 8)(lambda e, *a: 0)
reg("SearchPathA", 6)(lambda e, *a: (setattr(e, "last_error", 2), 0)[1])
reg("FormatMessageA", 7)(lambda e, *a: 0)


# ---- INI files (GetPrivateProfile*/WritePrivateProfile*, and WIN.INI via GetProfile*). MFC's
# CWinApp::GetProfileInt/String use these when the app set no registry key, which is the case for Max Payne.
# `Emu.ini_seed` = {(file, section, key): value} pre-loads "saved" settings (the native launcher's hook).
def _ini(e):
    if not hasattr(e, "ini"):
        e.ini = {}               # file (lower) -> section (lower) -> key (lower) -> (display key, value str)
        e.ini_log = []
        for (f, sec, key), val in getattr(e, "ini_seed", {}).items():
            e.ini.setdefault(f.lower(), {}).setdefault(sec.lower(), {})[key.lower()] = (key, str(val))
    return e.ini


def _ini_get(e, f, sec, key):
    return _ini(e).get(os.path.basename(f.replace("\\\\", "/")).lower(), {}).get(sec.lower(), {}).get(key.lower())


def _ini_file(e, ptr):
    return e.cstr(ptr) if ptr else "win.ini"


@reg("GetPrivateProfileIntA", 4)
def _(e, sec, key, default, f):
    s, k, fn = e.cstr(sec), e.cstr(key), _ini_file(e, f)
    v = _ini_get(e, fn, s, k)
    _ini(e)
    e.ini_log.append("get int    [%s] %s = %s (default %d) in %s" % (s, k, v[1] if v else "<missing>", default - (1 << 32) if default & 0x80000000 else default, os.path.basename(fn.replace("\\\\", "/"))))
    if v is None:
        return default
    try:
        return int(v[1].strip().split()[0], 0) & 0xFFFFFFFF
    except (ValueError, IndexError):
        return 0


@reg("GetProfileIntA", 3)
def _(e, sec, key, default):
    return HLE[(K, "GetPrivateProfileIntA")][0](e, sec, key, default, 0)


@reg("GetPrivateProfileStringA", 6)
def _(e, sec, key, default, buf, size, f):
    s, k, fn = e.cstr(sec) if sec else "", e.cstr(key) if key else "", _ini_file(e, f)
    v = _ini_get(e, fn, s, k)
    _ini(e)
    d = e.cstr(default) if default else ""
    out = (v[1] if v else d)
    e.ini_log.append("get string [%s] %s = %r (default %r) in %s" % (s, k, v[1] if v else "<missing>", d, os.path.basename(fn.replace("\\\\", "/"))))
    raw = out.encode("latin1")
    if size:
        e.wr(buf, raw[:size - 1] + b"\0")
    return min(len(raw), max(size - 1, 0))


@reg("WritePrivateProfileStringA", 4)
def _(e, sec, key, val, f):
    s, fn = e.cstr(sec) if sec else "", _ini_file(e, f)
    fk = os.path.basename(fn.replace("\\\\", "/")).lower()
    tbl = _ini(e).setdefault(fk, {})
    if key:
        k = e.cstr(key)
        if val:
            tbl.setdefault(s.lower(), {})[k.lower()] = (k, e.cstr(val))
            e.ini_log.append("write      [%s] %s = %r in %s" % (s, k, e.cstr(val), fk))
        else:
            tbl.get(s.lower(), {}).pop(k.lower(), None)
    else:
        tbl.pop(s.lower(), None)
    return 1


# atoms
def _atoms(e):
    if not hasattr(e, "_atoms"):
        e._atoms = {}
    return e._atoms


@reg("GlobalAddAtomA", 1)
def _(e, name):
    t = _atoms(e)
    n = e.cstr(name).lower()
    for k, v in t.items():
        if v == n:
            return k
    k = 0xC000 + len(t)
    t[k] = n
    return k


@reg("GlobalFindAtomA", 1)
def _(e, name):
    n = e.cstr(name).lower()
    return next((k for k, v in _atoms(e).items() if v == n), 0)


@reg("GlobalGetAtomNameA", 3)
def _(e, atom, buf, size):
    n = _atoms(e).get(atom, "")
    e.wr(buf, n.encode()[:size - 1] + b"\0")
    return len(n)


@reg("GlobalDeleteAtom", 1)
def _(e, atom):
    _atoms(e).pop(atom, None)
    return 0


# sync objects and threads (single-threaded bring-up: objects exist, nothing blocks)
reg("CreateSemaphoreA", 4)(lambda e, a, b, c, d: e.new_handle("semaphore"))
reg("ReleaseSemaphore", 3)(lambda e, h, n, prev: 1)
reg("WaitForMultipleObjects", 4)(lambda e, n, h, all_, ms: 0)
reg("SuspendThread", 1)(lambda e, h: 0)
reg("ResumeThread", 1)(lambda e, h: 1)
reg("VirtualProtect", 4)(lambda e, a, n, new, old: (e.wr32(old, 0x40) if old else None, 1)[1])


@reg("CreateThread", 6)
def _(e, sec, stack, fn, param, flags, ptid):
    print("[CreateThread] fn=%s param=0x%x flags=0x%x (not run: single-threaded bring-up)" % (e.module_at(fn), param, flags))
    if ptid:
        e.wr32(ptid, 0x200)
    return e.new_handle("thread", (fn, param))


@reg("ExitThread", 1)
def _(e, code): raise Unimplemented("ExitThread")


# resources: look up (type, name) in a loaded module's resource directory
def _res_key(e, v):
    return v if v < 0x10000 else e.cstr(v).upper()


def _find_resource(e, hmod, name, typ, wide=False):
    mod = next((m for m in e.modules.values() if m.base == hmod), None)
    if mod is None and hmod == 0:
        mod = e.modules.get("maxpayne.exe")
    if mod is None or not hasattr(mod.pe, "DIRECTORY_ENTRY_RESOURCE"):
        e.last_error = 1813
        return 0
    def key(v):
        if v < 0x10000:
            return v
        return (e.wstr(v) if wide else e.cstr(v)).upper()
    kt, kn = key(typ), key(name)
    for t in mod.pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tid = t.id if t.id is not None else (t.name.decode() if isinstance(t.name, bytes) else str(t.name)).upper()
        if tid != kt:
            continue
        for n in t.directory.entries:
            nid = n.id if n.id is not None else (n.name.decode() if isinstance(n.name, bytes) else str(n.name)).upper()
            if nid != kn:
                continue
            lang = n.directory.entries[0]
            d = lang.data.struct
            return e.new_handle("resource", (mod, d.OffsetToData, d.Size))
    e.last_error = 1814
    return 0


reg("FindResourceA", 3)(lambda e, h, n, t: _find_resource(e, h, n, t))
reg("FindResourceW", 3)(lambda e, h, n, t: _find_resource(e, h, n, t, True))


@reg("LoadResource", 2)
def _(e, hmod, hres):
    k = e.handles.get(hres)
    return (k[1][0].base + k[1][1]) if k and k[0] == "resource" else 0


reg("LockResource", 1)(lambda e, h: h)


@reg("SizeofResource", 2)
def _(e, hmod, hres):
    k = e.handles.get(hres)
    return k[1][2] if k and k[0] == "resource" else 0


@reg("LoadStringA", 4, dll="USER32.DLL")
def _(e, hinst, uid, buf, size):
    """String uid of the module's RT_STRING table (blocks of 16: block uid / 16 + 1, each string a length-prefixed
    UTF-16 run), as the ANSI code page, cut to size - 1 characters. Returns the length; 0 when there is none. MFC's
    AfxWinInit reads the app title (AFX_IDS_APP_TITLE) this way, which names the registry key of the settings."""
    h = _find_resource(e, hinst, (uid >> 4) + 1, 6)
    if not h or size <= 0:
        return 0
    mod, off, n = e.handles.pop(h)[1]
    data, pos = mod.pe.get_data(off, n), 0
    for _ in range(uid & 15):
        pos += 2 + 2 * struct.unpack_from("<H", data, pos)[0]
    ln = struct.unpack_from("<H", data, pos)[0]
    s = data[pos + 2:pos + 2 + 2 * ln].decode("utf-16le").encode("cp1252", "replace")[:size - 1]
    e.wr(buf, s + b"\0")
    return len(s)


# =============================================================================== HLE: USER32 / GDI32 / OLE32 / ADVAPI32
# Bring-up behaviour: no real windows exist yet (the renderer/window layer is built in M3/M4), so these
# answer plausibly. SCREEN is what the game sees as the desktop size: the M7 target, 2560x1600 (16:10).
SCREEN = (2560, 1600)
U, G = "USER32.DLL", "GDI32.DLL"


def _simple(dll, table):
    for name, (nargs, val) in table.items():
        hle(dll, name, nargs)(lambda e, *a, _v=val: _v)


_simple(U, {
    "FindWindowA": (2, 0), "GetActiveWindow": (0, 0x1000), "GetDesktopWindow": (0, 0x1001),
    "GetDC": (1, 0x2000), "ReleaseDC": (2, 1), "GetDlgCtrlID": (1, 0), "GetLastActivePopup": (1, 0x1000),
    "IsIconic": (1, 0), "EnableWindow": (2, 1), "ShowWindow": (2, 1),
    "InvalidateRect": (3, 1), "RedrawWindow": (4, 1), "SetForegroundWindow": (1, 1),
    "SendMessageA": (4, 0), "PostQuitMessage": (1, 0), "SetCursor": (1, 0),
    "LoadCursorA": (2, 0x3001), "LoadIconA": (2, 0x3002), "LoadAcceleratorsA": (2, 0x3003),
    "TranslateAcceleratorA": (3, 0), "TranslateMessage": (1, 0), "DispatchMessageA": (1, 0),
    "PeekMessageA": (5, 0), "GetMessageA": (4, 0), "SetWindowsHookExA": (4, 0x4000),
    "UnhookWindowsHookEx": (1, 1), "CallNextHookEx": (4, 0), "GetAsyncKeyState": (1, 0),
    "SystemParametersInfoA": (4, 1), "FillRect": (3, 1), "DrawTextA": (5, 0), "DrawTextW": (5, 0),
    "ToAscii": (5, 0), "GetKeyNameTextA": (3, 0),
})
_simple(G, {
    "CreateCompatibleDC": (1, 0x2100), "CreateCompatibleBitmap": (3, 0x2101), "DeleteDC": (1, 1),
    "DeleteObject": (1, 1), "SelectObject": (2, 0x2102), "SetBkColor": (2, 0), "SetBkMode": (2, 1),
    "SetTextColor": (2, 0), "SetMapMode": (2, 1), "GetMapMode": (1, 1), "BitBlt": (9, 1),
    "CreateFontIndirectA": (1, 0x2103), "GetObjectA": (3, 0),
})
_simple("OLE32.DLL", {"CoInitialize": (1, 0), "CoUninitialize": (0, 0)})
_simple("ADVAPI32.DLL", {"RegSetValueA": (5, 0)})   # the game's registry writes are not performed


@reg("GetSystemMetrics", 1, dll=U)
def _(e, i): return {0: SCREEN[0], 1: SCREEN[1], 4: 19, 5: 1, 6: 1, 7: 3, 8: 3, 15: 20}.get(i, 0)


@reg("IsWindow", 1, dll=U)
def _(e, h): return 1 if h else 0


@reg("GetClientRect", 2, dll=U)
def _(e, h, p):
    e.wr(p, struct.pack("<4i", 0, 0, SCREEN[0], SCREEN[1]))
    return 1


@reg("GetWindowRect", 2, dll=U)
def _(e, h, p):
    e.wr(p, struct.pack("<4i", 0, 0, SCREEN[0], SCREEN[1]))
    return 1


@reg("ClientToScreen", 2, dll=U)
def _(e, h, p): return 1


@reg("GetKeyboardState", 1, dll=U)
def _(e, p):
    e.wr(p, b"\0" * 256)
    return 1


@reg("MessageBoxA", 4, dll=U)
def _(e, h, text, caption, flags):
    print("[MessageBox] %s: %s" % (e.cstr(caption), e.cstr(text)))
    return 1


@reg("GetDeviceCaps", 2, dll=G)
def _(e, dc, idx): return {8: SCREEN[0], 10: SCREEN[1], 12: 32, 14: 1, 88: 96, 90: 96, 24: 0}.get(idx, 0)


@reg("CreateDIBSection", 6, dll=G)
def _(e, dc, bmi, usage, ppbits, section, off):
    w, h = struct.unpack("<ii", e.rd(bmi + 4, 8))
    bpp = struct.unpack("<H", e.rd(bmi + 14, 2))[0]
    mem = e.alloc(abs(w) * abs(h) * max(bpp // 8, 1) + 64)
    if ppbits:
        e.wr32(ppbits, mem)
    return e.new_handle("dib", mem)


@reg("GetDIBits", 7, dll=G)
def _(e, dc, bmp, start, lines, bits, bmi, usage): return lines


# COM classes the HLE layers provide: CLSID (16 bytes, little-endian GUID) -> (name, factory(e, outer, iid, ppv)
# returning an HRESULT). dsound.py registers DirectSound, dshow.py the DirectShow filter graph.
COM_CLASSES = {}


@reg("CoCreateInstance", 5, dll="OLE32.DLL")
def _(e, clsid, outer, ctx, iid, ppv):
    import uuid
    c, i = e.rd(clsid, 16), e.rd(iid, 16)
    log = e.__dict__.setdefault("com_log", [])
    if c in COM_CLASSES:
        name, factory = COM_CLASSES[c]
        hr = factory(e, outer, i, ppv) & 0xFFFFFFFF
        log.append("CoCreateInstance(%s, iid %s) -> 0x%x" % (name, uuid.UUID(bytes_le=i), hr))
        return hr
    if ppv:
        e.wr32(ppv, 0)
    log.append("CoCreateInstance(%s, iid %s) -> REGDB_E_CLASSNOTREG" % (uuid.UUID(bytes_le=c), uuid.UUID(bytes_le=i)))
    return 0x80040154        # REGDB_E_CLASSNOTREG


# #296 is CCommandLineInfo::CCommandLineInfo() (thiscall). Layout (MFC 4.2, derives from CObject):
# +0 vtable, +4 m_bShowSplash, +8 m_bRunEmbedded, +0xc m_bRunAutomated, +0x10 m_nShellCommand,
# +0x14.. four CStrings (file name, printer, driver, port). Confirmed by maxpayne.exe+0xa5d1, which reads
# the CString at +0x14 and measures it via the length field at [data - 8].
@reg("#296", 0, dll="MFC42.DLL")
def _(e):
    this = e.ecx()
    e.wr(this + 4, struct.pack("<IIII", 1, 0, 0, 0))
    for off in (0x14, 0x18, 0x1C, 0x20):
        e.wr32(this + off, e.empty_cstring())
    return this


# The game keeps its settings in the registry through CWinApp::GetProfileInt/GetProfileString.
# For now these return the supplied defaults; a native settings file (resolution, fps cap) plugs in here.
@reg("#3521", 3, dll="MFC42.DLL")    # CWinApp::GetProfileInt(section, entry, default)
def _(e, section, entry, default): return default


@reg("#3522", 4, dll="MFC42.DLL")    # CWinApp::GetProfileString(&result, section, entry, default)
def _(e, out, section, entry, default):
    e.wr32(out, e.new_cstring(e.cstr(default) if default else ""))
    return out


# ---- the long tail of USER32/GDI32 that real MFC42 imports. Argument counts are the documented stdcall
# signatures; with no real windows yet, most return 0. A few return values MFC's start-up cares about.
_USER_ARGS = dict(
    AdjustWindowRectEx=4, AppendMenuA=4, BeginDeferWindowPos=1, BeginPaint=2, BringWindowToTop=1,
    CallWindowProcA=5, CharNextA=1, CharToOemA=2, CharUpperA=1, CheckDlgButton=3, CheckMenuItem=3,
    CheckRadioButton=4, ClipCursor=1, CopyAcceleratorTableA=3, CopyRect=2, CountClipboardFormats=0,
    CreateDialogIndirectParamA=5, CreateMenu=0, CreateWindowExA=12, DefFrameProcA=5, DefMDIChildProcA=4,
    DefWindowProcA=4, DeferWindowPos=8, DeleteMenu=3, DestroyCursor=1, DestroyIcon=1, DestroyMenu=1,
    DestroyWindow=1, DrawEdge=4, DrawFocusRect=2, DrawMenuBar=1, EnableMenuItem=3, EndDeferWindowPos=1,
    EndDialog=2, EndPaint=2, EnumChildWindows=3, EqualRect=2, FrameRect=3, GetCapture=0, GetClassInfoA=3,
    GetClassLongA=2, GetClassNameA=3, GetCursorPos=1, GetDCEx=3, GetDialogBaseUnits=0, GetDlgItem=2,
    GetDlgItemInt=4, GetDlgItemTextA=4, GetFocus=0, GetForegroundWindow=0, GetKeyState=1, GetMenu=1,
    GetMenuCheckMarkDimensions=0, GetMenuItemCount=1, GetMenuItemID=2, GetMenuState=3, GetMenuStringA=5,
    GetMessagePos=0, GetMessageTime=0, GetNextDlgGroupItem=3, GetNextDlgTabItem=3, GetParent=1,
    GetPropA=2, GetScrollInfo=3, GetScrollPos=2, GetScrollRange=4, GetSubMenu=2, GetSysColor=1,
    GetSysColorBrush=1, GetSystemMenu=2, GetTabbedTextExtentA=5, GetTopWindow=1, GetWindow=2,
    GetWindowDC=1, GetWindowLongA=2, GetWindowPlacement=2, GetWindowTextA=3, GetWindowTextLengthA=1,
    GetWindowThreadProcessId=2, GrayStringA=9, InSendMessage=0, InflateRect=3, InsertMenuA=5,
    IntersectRect=3, InvalidateRgn=3, InvertRect=2, IsChild=2, IsClipboardFormatAvailable=1,
    IsDialogMessageA=2, IsDlgButtonChecked=2, IsRectEmpty=1, IsWindowEnabled=1, IsWindowVisible=1,
    IsZoomed=1, KillTimer=2, LoadBitmapA=2, LoadMenuA=2, LoadStringA=4, LockWindowUpdate=1,
    MapDialogRect=2, MapWindowPoints=4, MessageBeep=1, ModifyMenuA=5, MoveWindow=6,
    MsgWaitForMultipleObjects=5, OemToCharA=2, OffsetRect=3, PostMessageA=4, PostThreadMessageA=4,
    PtInRect=3, RegisterClassA=1, RegisterClipboardFormatA=1, RegisterWindowMessageA=1, ReleaseCapture=0,
    RemoveMenu=3, RemovePropA=2, ReuseDDElParam=5, ScreenToClient=2, ScrollWindow=5, ScrollWindowEx=8,
    SendDlgItemMessageA=5, SetActiveWindow=1, SetCapture=1, SetCursorPos=2, SetDlgItemInt=4,
    SetDlgItemTextA=3, SetFocus=1, SetMenu=2, SetMenuItemBitmaps=5, SetParent=2, SetPropA=3, SetRect=5,
    SetRectEmpty=1, SetScrollInfo=4, SetScrollPos=4, SetScrollRange=5, SetTimer=4,
    SetWindowContextHelpId=2, SetWindowLongA=3, SetWindowPlacement=2, SetWindowPos=7, SetWindowTextA=2,
    ShowOwnedPopups=2, ShowScrollBar=3, TabbedTextOutA=8, TrackPopupMenu=7, TranslateMDISysAccel=2,
    UnionRect=3, UnpackDDElParam=4, UnregisterClassA=2, UpdateWindow=1, ValidateRect=2, WaitMessage=0,
    WinHelpA=4, WindowFromDC=1, WindowFromPoint=2, wvsprintfA=3,
)
_GDI_ARGS = dict(
    AbortDoc=1, ArcTo=9, CloseMetaFile=1, CombineRgn=4, CopyMetaFileA=2, CreateBitmap=5, CreateDCA=4,
    CreateDIBPatternBrushPt=2, CreateFontA=14, CreateHatchBrush=2, CreateMetaFileA=1, CreatePalette=1,
    CreatePatternBrush=1, CreatePen=3, CreateRectRgn=4, CreateRectRgnIndirect=1, CreateSolidBrush=1,
    DPtoLP=3, DeleteMetaFile=1, EndDoc=1, EndPage=1, EnumFontFamiliesA=4, EnumMetaFile=4, Escape=5,
    ExcludeClipRect=5, ExtCreatePen=5, ExtSelectClipRgn=3, ExtTextOutA=8, GetBkColor=1, GetBkMode=1,
    GetCharWidthA=4, GetClipBox=2, GetClipRgn=2, GetCurrentPositionEx=2, GetNearestColor=2,
    GetObjectType=1, GetPaletteEntries=4, GetPixel=3, GetPolyFillMode=1, GetROP2=1, GetStockObject=1,
    GetStretchBltMode=1, GetTextAlign=1, GetTextColor=1, GetTextExtentPoint32A=4, GetTextFaceA=3,
    GetTextMetricsA=2, GetViewportExtEx=2, GetViewportOrgEx=2, GetWindowExtEx=2, GetWindowOrgEx=2,
    IntersectClipRect=5, LPtoDP=3, LineTo=3, MoveToEx=4, OffsetClipRgn=3, OffsetRgn=3,
    OffsetViewportOrgEx=4, OffsetWindowOrgEx=4, PatBlt=6, PlayMetaFile=2, PlayMetaFileRecord=4,
    PolyBezierTo=3, PolyDraw=4, PolylineTo=3, PtVisible=3, RealizePalette=1, RectVisible=2, Rectangle=5,
    RestoreDC=2, SaveDC=1, ScaleViewportExtEx=6, ScaleWindowExtEx=6, SelectClipPath=2, SelectClipRgn=2,
    SelectPalette=3, SetAbortProc=2, SetArcDirection=2, SetBrushOrgEx=4, SetColorAdjustment=2,
    SetMapperFlags=2, SetPolyFillMode=2, SetROP2=2, SetRectRgn=5, SetStretchBltMode=2, SetTextAlign=2,
    SetTextCharacterExtra=2, SetTextJustification=3, SetViewportExtEx=4, SetViewportOrgEx=4,
    SetWindowExtEx=4, SetWindowOrgEx=4, StartDocA=2, StartPage=1, StretchDIBits=13, TextOutA=5,
    UnrealizeObject=1,
)
_DEFAULT_RET = {
    "GetSysColor": 0x00C0C0C0, "GetSysColorBrush": 0x2200, "GetStockObject": 0x2201,
    "GetDialogBaseUnits": (16 << 16) | 8, "SaveDC": 1, "RestoreDC": 1, "CreateSolidBrush": 0x2202,
    "CreatePen": 0x2203, "CreateRectRgn": 0x2204, "CreateFontA": 0x2205, "CreateBitmap": 0x2206,
    "GetObjectType": 1, "GetTextColor": 0, "GetBkMode": 1, "CharNextA": None,
}
for _n, _a in _USER_ARGS.items():
    if (U, _n) not in HLE:
        hle(U, _n, _a)(lambda e, *a, _v=_DEFAULT_RET.get(_n, 0): 0 if _v is None else _v)
for _n, _a in _GDI_ARGS.items():
    if (G, _n) not in HLE:
        hle(G, _n, _a)(lambda e, *a, _v=_DEFAULT_RET.get(_n, 0): _v)


@reg("CharNextA", 1, dll=U)
def _(e, p): return p + (1 if e.rd(p, 1) != b"\0" else 0)


_msg_atoms = {}


@reg("RegisterWindowMessageA", 1, dll=U)
def _(e, name):
    return _msg_atoms.setdefault(e.cstr(name), 0xC100 + len(_msg_atoms))


@reg("RegisterClipboardFormatA", 1, dll=U)
def _(e, name):
    return _msg_atoms.setdefault("clip:" + e.cstr(name), 0xC100 + len(_msg_atoms))


@reg("RegisterClassA", 1, dll=U)
def _(e, wc): return 0xC200 + (e.rd32(wc + 0x24) & 0xFF if False else 0)


@reg("wsprintfA", 2, cc="cdecl", dll=U)
def _(e, buf, fmt):
    # varargs: the guest pushed them after (buf, fmt); read them straight off the stack
    sp = e.uc.reg_read(UC_X86_REG_ESP) + 12
    out, i, f = [], 0, e.cstr(fmt)
    k = 0
    while k < len(f):
        c = f[k]
        if c != "%":
            out.append(c)
            k += 1
            continue
        k += 1
        spec = ""
        while k < len(f) and f[k] in "-+ #0123456789.l":
            spec += f[k]
            k += 1
        t = f[k] if k < len(f) else ""
        k += 1
        v = e.rd32(sp + 4 * i)
        i += 1
        if t == "s":
            out.append(e.cstr(v))
        elif t in "di":
            out.append(str(v - (1 << 32) if v & 0x80000000 else v))
        elif t == "u":
            out.append(str(v))
        elif t in "xX":
            out.append(("%x" if t == "x" else "%X") % v)
        elif t == "c":
            out.append(chr(v & 0xFF))
        elif t == "%":
            out.append("%")
            i -= 1
    res = "".join(out).encode("latin1", "replace")
    e.wr(buf, res + b"\0")
    return len(res)


# ---- registry (ADVAPI32, reached through MFC's delay-load and the exe's own RegSetValueA).
# Kept in <data>/registry.json (see data_dir) and written through on every change, so settings, the last saved
# game and the parental lock persist between runs like on Windows. `Emu.registry_seed` supplies defaults for
# values that are not there yet (this is how the native launcher's settings skip the startup dialog);
# `Emu.registry_overrides` replaces values (launcher options the player changed). Key paths and value names are
# stored lower-case: the registry is case-insensitive.
A = "ADVAPI32.DLL"
ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_MORE_DATA = 2, 259, 234
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD = 1, 2, 3, 4
HKEY_ROOTS = {0x80000000: "HKCR", 0x80000001: "HKCU", 0x80000002: "HKLM", 0x80000003: "HKU"}


def _reg_value(val):
    """Python value (int for a DWORD, str for a string) as a registry (type, data) pair."""
    if isinstance(val, int):
        return REG_DWORD, struct.pack("<I", val & 0xFFFFFFFF)
    return REG_SZ, str(val).encode("latin1") + b"\0"


def _reg_file(e):
    return os.path.join(data_dir(e), "registry.json")


def _reg_load(e):
    import json
    try:
        doc = json.load(open(_reg_file(e)))
    except (OSError, ValueError):
        return {}
    st = {}
    for key, values in doc.get("keys", {}).items():
        d = st.setdefault(key.lower(), {})
        for name, v in values.items():
            if "dword" in v:
                d[name.lower()] = (REG_DWORD, struct.pack("<I", v["dword"] & 0xFFFFFFFF))
            elif "string" in v:
                d[name.lower()] = (v.get("type", REG_SZ), v["string"].encode("latin1") + b"\0")
            else:
                d[name.lower()] = (v.get("type", REG_BINARY), bytes.fromhex(v.get("hex", "")))
    return st


def _reg_save(e):
    """Write the registry to <data>/registry.json (atomically)."""
    import json
    keys = {}
    for key, values in sorted(e.registry.items()):
        out = keys.setdefault(key, {})
        for name, (typ, data) in sorted(values.items()):
            if typ == REG_DWORD and len(data) == 4:
                out[name] = {"dword": struct.unpack("<I", data)[0]}
            elif typ in (REG_SZ, REG_EXPAND_SZ) and data.endswith(b"\0") and b"\0" not in data[:-1]:
                out[name] = {"type": typ, "string": data[:-1].decode("latin1")}
            else:
                out[name] = {"type": typ, "hex": data.hex()}
    tmp = _reg_file(e) + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"version": 1, "keys": keys}, f, indent=1)
    os.replace(tmp, _reg_file(e))


def _reg_key(st, path):
    """The value dict of key `path`, creating it and every missing key on the way, as Windows does."""
    parts = path.lower().split("\\")
    for i in range(2, len(parts) + 1):
        st.setdefault("\\".join(parts[:i]), {})
    return st[path.lower()]


def _regstore(e):
    if not hasattr(e, "registry"):
        e.registry = {"hkcu\\software": {}, "hklm\\software": {}, "hkcr": {}}   # keys every Windows has
        e.reg_handles = {}       # handle -> key path
        e.reg_next = 0x5000
        e.reg_log = []
        for key, values in _reg_load(e).items():
            e.registry.setdefault(key, {}).update(values)
        _reg_apply(e)
    return e.registry


def _reg_apply(e):
    """Apply Emu.registry_seed and Emu.registry_overrides to the loaded store and save it (at load; launcher.py again
    when it loaded the store before setting them)."""
    for (path, name), val in getattr(e, "registry_seed", {}).items():
        _reg_key(e.registry, path).setdefault(name.lower(), _reg_value(val))
    for (path, name), val in getattr(e, "registry_overrides", {}).items():
        _reg_key(e.registry, path)[name.lower()] = _reg_value(val)
    _reg_save(e)


def _reg_open(e, hkey, sub, create):
    st = _regstore(e)
    base = HKEY_ROOTS.get(hkey) or e.reg_handles.get(hkey)
    if base is None:
        return None
    path = base if not sub else base + "\\" + sub
    if create:
        if path.lower() not in st:
            _reg_key(st, path)
            _reg_save(e)
    elif path.lower() not in st:
        e.reg_log.append("open   %s -> not found" % path)
        return None
    h = e.reg_next                    # a counter: handles of closed keys are never reused while others are open
    e.reg_next += 4
    e.reg_handles[h] = path
    e.reg_log.append("%s %s -> handle 0x%x" % ("create" if create else "open  ", path, h))
    return h


@reg("RegCreateKeyExA", 9, dll=A)
def _(e, hk, sub, r, cls, opt, sam, sec, phk, disp):
    h = _reg_open(e, hk, e.cstr(sub) if sub else "", True)
    e.reg_log.append("create %s -> %s" % (e.reg_handles.get(h), "ok" if h else "fail"))
    if h is None:
        return 6
    e.wr32(phk, h)
    if disp:
        e.wr32(disp, 2)      # REG_OPENED_EXISTING_KEY
    return 0


@reg("RegCreateKeyA", 3, dll=A)
def _(e, hk, sub, phk):
    h = _reg_open(e, hk, e.cstr(sub) if sub else "", True)
    if h is None:
        return 6
    e.wr32(phk, h)
    return 0


@reg("RegOpenKeyExA", 5, dll=A)
def _(e, hk, sub, opt, sam, phk):
    h = _reg_open(e, hk, e.cstr(sub) if sub else "", False)
    if h is None:
        return ERROR_FILE_NOT_FOUND
    e.wr32(phk, h)
    return 0


@reg("RegOpenKeyA", 3, dll=A)
def _(e, hk, sub, phk):
    h = _reg_open(e, hk, e.cstr(sub) if sub else "", False)
    if h is None:
        return ERROR_FILE_NOT_FOUND
    e.wr32(phk, h)
    return 0


@reg("RegQueryValueExA", 6, dll=A)
def _(e, hk, name, reserved, ptype, pdata, pcb):
    path = e.reg_handles.get(hk)
    vname = e.cstr(name) if name else ""
    val = _regstore(e).get((path or "").lower(), {}).get(vname.lower())
    e.reg_log.append("query  %s \\ %s -> %s" % (path, vname, "found %r" % (val[1][:24],) if val else "not found"))
    if val is None:
        return ERROR_FILE_NOT_FOUND
    typ, data = val
    if ptype:
        e.wr32(ptype, typ)
    if pcb:
        cap = e.rd32(pcb)
        e.wr32(pcb, len(data))
        if pdata:
            if cap < len(data):
                return ERROR_MORE_DATA
            e.wr(pdata, data)
    return 0


@reg("RegSetValueExA", 6, dll=A)
def _(e, hk, name, reserved, typ, pdata, cb):
    path = e.reg_handles.get(hk)
    vname = e.cstr(name) if name else ""
    data = e.rd(pdata, cb)
    if path is None:
        return 6                                          # ERROR_INVALID_HANDLE
    _regstore(e).setdefault(path.lower(), {})[vname.lower()] = (typ, data)
    _reg_save(e)
    e.reg_log.append("set    %s \\ %s = type %d %r" % (path, vname, typ, data[:24]))
    return 0


@reg("RegSetValueA", 5, dll=A)
def _(e, hk, sub, typ, pdata, cb):
    base = HKEY_ROOTS.get(hk) or e.reg_handles.get(hk) or "?"
    path = base + ("\\" + e.cstr(sub) if sub else "")
    _regstore(e).setdefault(path.lower(), {})[""] = (REG_SZ, e.cstr(pdata).encode("latin1") + b"\0")
    _reg_save(e)
    return 0


@reg("RegDeleteValueA", 2, dll=A)
def _(e, hk, name):
    path = e.reg_handles.get(hk) or HKEY_ROOTS.get(hk)
    vname = (e.cstr(name) if name else "").lower()
    values = _regstore(e).get((path or "").lower())
    if values is None or vname not in values:
        return ERROR_FILE_NOT_FOUND
    del values[vname]
    _reg_save(e)
    e.reg_log.append("delete %s \\ %s" % (path, vname))
    return 0


@reg("RegDeleteKeyA", 2, dll=A)
def _(e, hk, sub):
    """Delete a key that has no subkeys (Windows NT semantics)."""
    base = e.reg_handles.get(hk) or HKEY_ROOTS.get(hk)
    if base is None or not sub:
        return 6
    path = (base + "\\" + e.cstr(sub)).lower()
    st = _regstore(e)
    if path not in st:
        return ERROR_FILE_NOT_FOUND
    if any(k.startswith(path + "\\") for k in st):
        return 5                                          # ERROR_ACCESS_DENIED: has subkeys
    del st[path]
    _reg_save(e)
    e.reg_log.append("delete %s" % path)
    return 0


reg("RegQueryValueA", 4, dll=A)(lambda e, *a: ERROR_FILE_NOT_FOUND)
reg("RegCloseKey", 1, dll=A)(lambda e, h: (e.reg_handles.pop(h, None), 0)[1])
reg("RegFlushKey", 1, dll=A)(lambda e, h: 0)
reg("RegEnumKeyA", 4, dll=A)(lambda e, *a: ERROR_NO_MORE_ITEMS)
reg("RegEnumKeyExA", 8, dll=A)(lambda e, *a: ERROR_NO_MORE_ITEMS)


# MFC42 state accessors the exe's start-up uses. #1168 returns a pointer to a per-module state block
# (the code at maxpayne.exe+0x783878 stores a flag at +0x14 and a code page at +0x1040 into it).
@reg("#1168", 0, dll="MFC42.DLL")
def _(e):
    if not hasattr(e, "afx_state"):
        e.afx_state = e.alloc(0x4000)
    return e.afx_state


# =============================================================================== driver
GAME_DLLS = [
    "MSVCRT.DLL", "MSVCIRT.DLL", "MSVCP60.DLL", "MFC42.DLL",
    "rlmfc.dll", "grphmfc.dll", "e2mfc.dll", "sndmfc.dll",
]


def boot(game_dir, verbose=True, with_exe=False):
    import d3d8
    import winsys
    import dsound
    import dinput
    import dshow
    d3d8.install(sys.modules[__name__])      # Direct3D 8 (logging) HLE: Direct3DCreate8 and the COM objects
    winsys.install(sys.modules[__name__])    # minimal Win32 window manager (classes, CreateWindowEx, messages)
    dsound.install(sys.modules[__name__])    # DirectSound: enumeration, COM creation, buffers, 3D listener
    dinput.install(sys.modules[__name__])    # DirectInput 7: keyboard/mouse devices, plus USER32 key queries
    dshow.install(sys.modules[__name__])     # DirectShow filter graph: the intro movie (AVFoundation decoding)
    e = Emu(game_dir)
    e.win_log = []
    for rel in GAME_DLLS:
        e.load_module(rel)
    if with_exe:
        e.load_module("MaxPayne.exe")
    for m in list(e.modules.values()):
        e.resolve_imports(m)
    return e


def run_dll_mains(e, verbose=True):
    ok = True
    for name in [n.lower() for n in GAME_DLLS]:
        m = e.modules[name]
        if not m.entry:
            continue
        r = e.call(m.entry, m.base, 1, 0)
        status = "ok" if not e.fatal else "FAILED"
        if verbose:
            print("DllMain %-12s entry=%s -> eax=%d  %s" % (name, e.module_at(m.entry), r, status))
        if e.fatal:
            print("   fatal:", e.fatal)
            print("   at:", e.where(), "->", e.module_at(e.uc.reg_read(UC_X86_REG_EIP)))
            print("   last API calls:")
            for line in list(e.apilog)[-8:]:
                print("     ", line)
            ok = False
            break
    return ok


if __name__ == "__main__":
    game = sys.argv[1] if len(sys.argv) > 1 else "Max Payne"
    emu = boot(game)
    print("loaded:", ", ".join("%s@0x%x" % (m.name, m.base) for m in emu.modules.values()))
    missing = sorted(k for k in emu.unresolved if k not in HLE)
    print("imports bound to stubs:", len(emu.unresolved), " without HLE handler:", len(missing))
    run_dll_mains(emu)
