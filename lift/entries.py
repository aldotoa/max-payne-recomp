"""Function entries of a lift/functions.py inventory, and VA lists in text (lift/build.py, emu/native.py).

Kept apart from emu/native.py so the lift needs no emulator (no unicorn import).
"""
import json
import re


def function_entries(inventory_path, patchable=True):
    """The entries of a function inventory (lift/functions.py) that are real function entries: every entry that is not
    a gap-scan find, the gap-scan finds that another function calls, and the address-taken ones (a code pointer in the
    image refers to them). A gap-scan find can be a label inside another function (reached by a jump, or as an SEH
    continuation): entering it does not mean a call, and patching it would overwrite code of the function it sits in.
    Inventories that predate "address_taken" count as not address-taken. Returns a set of va.
    patchable: leave out the entries whose 5-byte patch would overlap another function's code (below). The emulator's
    patching needs that; the lift does not (lift/build.py --entries real passes False): such an entry is lifted, lifted
    callers reach it through the table, and emulated code keeps entering the emulated copy."""
    with open(inventory_path) as fh:
        inv = json.load(fh)

    def va_of(x):
        return int(x, 16) if isinstance(x, str) else int(x)
    called = set()
    for f in inv["functions"]:
        for key in ("calls", "tail_calls"):
            called.update(va_of(x) for x in f.get(key, []))
    real = {va_of(f["entry"]) for f in inv["functions"]
            if not f.get("gap_scan") or va_of(f["entry"]) in called or f.get("address_taken", False)}
    if not patchable:
        return real
    # An entry whose 5 patched bytes overlap code of another function (an address-taken label, or a seed the linear
    # walk swallowed into a neighbour's padding) would corrupt that function's emulated path: leave it emulated.
    spans = sorted((va_of(b["start"]), va_of(b["end"]), va_of(f["entry"])) for f in inv["functions"]
                   if va_of(f["entry"]) in real for b in f.get("blocks", []))
    # Sweep the entries in address order. The spans that can overlap entry va's 5 bytes are the prefix with lo < va + 5
    # (spans sorted by lo; the prefix grows as va grows). va is excluded when a prefix span has hi > va and an owner
    # other than va, so only the largest hi per owner matters: keep the largest hi (best) and the largest hi among
    # spans of another owner (second), which answers the query for va in O(1).
    keep = set()
    best = second = None                               # (hi, owner)
    i, n = 0, len(spans)
    for va in sorted(real):
        while i < n and spans[i][0] < va + 5:
            _, hi, owner = spans[i]
            i += 1
            if best is None:
                best = (hi, owner)
            elif owner == best[1]:
                best = max(best, (hi, owner))
            elif hi > best[0]:
                second, best = best, (hi, owner)
            elif second is None or hi > second[0]:
                second = (hi, owner)
        cand = best if best is not None and best[1] != va else second
        if cand is None or cand[0] <= va:
            keep.add(va)
    return keep


_HEX_VA = re.compile(r"(?:0[xX])?[0-9a-fA-F]+")


def parse_va_text(text):
    """A set of VAs from text: hex numbers (with or without 0x) separated by commas or whitespace, one list per line
    or many; '#' starts a comment to the end of the line; blank lines are skipped and duplicates collapse. This is the
    value of a --diff-only style flag and the content of a --diff-only-file (one hex VA per line). A bad token raises
    ValueError naming every bad token."""
    vas, bad = set(), []
    for line in text.splitlines():
        for tok in line.split("#", 1)[0].replace(",", " ").split():
            if _HEX_VA.fullmatch(tok):
                vas.add(int(tok, 16))
            else:
                bad.append(tok)
    if bad:
        raise ValueError("not hex VAs: " + ", ".join(bad))
    return vas
