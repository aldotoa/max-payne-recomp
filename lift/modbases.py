"""Load addresses of the game DLLs and the base-relocation rule for mapping a PE at another base.

MODULE_BASES is a copy of emu/mpemu.py's dict (test_functions asserts they match). The emulator
maps each DLL there, so lifted code must use the same addresses: base=None means MODULE_BASES.
"""
import os

MODULE_BASES = {
    "rlmfc.dll": 0x10000000,
    "e2mfc.dll": 0x10100000,
    "grphmfc.dll": 0x10200000,
    "sndmfc.dll": 0x10300000,
    "e2_d3d8_driver_mfc.dll": 0x10400000,
}
IMAGE_REL_BASED_HIGHLOW = 3


def target_base(path, preferred, base=None):
    """The base to map the PE at `path`: `base` if given, else the emulator's load base."""
    if base is not None:
        return base
    return MODULE_BASES.get(os.path.basename(path).lower(), preferred)


def highlow_fixups(pe, delta):
    """[(rva, value)] for every IMAGE_REL_BASED_HIGHLOW site: the dword currently at rva (as
    stored in the file for the preferred base) plus delta, mod 2**32. Apply with the image's
    own bytes; `pe` itself is not modified."""
    out = []
    for blk in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for ent in blk.entries:
            if ent.type == IMAGE_REL_BASED_HIGHLOW:
                old = pe.get_dword_at_rva(ent.rva)
                assert old is not None, "relocation site outside the file image: 0x%x" % ent.rva
                out.append((ent.rva, (old + delta) & 0xFFFFFFFF))
    return out
