"""String instructions (M5): movs, stos, lods, scas, cmps, with no prefix, rep, repe/repz and
repne/repnz. The C helpers are in lift/runtime/strops.h; each handler emits one call such as
`str_rep_movs(c, 4);`.

Capstone puts the repeat kind in the mnemonic ("rep movsd", "repe cmpsb", "repne scasb") and omits
an F2 prefix on movs that the CPU ignores ("f2 a5" shows as plain "movsd"). The prefix is therefore
read from the raw bytes, and the element size from the opcode byte (0x66 makes a movs/stos/lods/
scas/cmps with a 4-byte element into 2 bytes, except the byte forms).

Rejected (the translator emits UNSUPPORTED): segment overrides, 0x67, lock, repeated prefixes,
repne on movs/stos/lods, and the SSE2 cmpsd/movsd forms (opcode 0f xx, not a string opcode).
"""
from x86c import Reject, handler

_OPC = {
    0xa4: ("movs", 1), 0xa5: ("movs", None),
    0xa6: ("cmps", 1), 0xa7: ("cmps", None),
    0xaa: ("stos", 1), 0xab: ("stos", None),
    0xac: ("lods", 1), 0xad: ("lods", None),
    0xae: ("scas", 1), 0xaf: ("scas", None),
}
_SEG = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65}
_PREFIX = _SEG | {0xf0, 0xf2, 0xf3, 0x66, 0x67}


def _form(ins):
    """(kind, element size, repeat mode) for a string instruction; Reject for anything else.
    repeat mode: "one", "rep", "repe" or "repne"."""
    raw = bytes(ins.bytes)
    i = 0
    while i < len(raw) and raw[i] in _PREFIX:
        i += 1
    if i >= len(raw):
        raise Reject("no opcode")
    prefixes, opc = raw[:i], raw[i]
    if opc not in _OPC:
        raise Reject("not a string opcode %02x" % opc)     # e.g. f2 0f c2: SSE2 cmpsd xmm
    if ins.size != i + 1:
        raise Reject("string instruction with extra bytes")
    for p in prefixes:
        if p in _SEG:
            raise Reject("segment override on a string instruction")
        if p == 0xf0:
            raise Reject("lock on a string instruction")
        if p == 0x67:
            raise Reject("address-size prefix")
    if prefixes.count(0x66) > 1:
        raise Reject("repeated operand-size prefix")
    reps = [p for p in prefixes if p in (0xf2, 0xf3)]
    if len(reps) > 1:
        raise Reject("repeated rep prefix")

    kind, size = _OPC[opc]
    if size is None:
        size = 2 if 0x66 in prefixes else 4
    if not reps:
        mode = "one"
    elif kind in ("cmps", "scas"):
        mode = "repe" if reps[0] == 0xf3 else "repne"
    elif reps[0] == 0xf3:
        mode = "rep"
    else:
        raise Reject("repne on %s" % kind)                 # the CPU ignores it; do not guess
    return kind, size, mode


def _lines(ins):
    kind, size, mode = _form(ins)
    fn = "str_%s%s" % ("" if mode == "one" else mode + "_", kind)
    return ["%s(c, %d);" % (fn, size)]


@handler(*[name for base in ("movsb", "movsw", "movsd", "stosb", "stosw", "stosd",
                             "lodsb", "lodsw", "lodsd", "scasb", "scasw", "scasd",
                             "cmpsb", "cmpsw", "cmpsd")
           for name in (base, "rep " + base, "repe " + base, "repz " + base,
                        "repne " + base, "repnz " + base)])
def h_string(ctx, ins):
    return _lines(ins)
