"""Unit tests for the per-user platform layer: the persistent registry, guest file locations (game folder overlay,
C: drive, My Documents and the saved-game folder), SHELL32 folder lookup, and the native launcher options.

Every test uses its own temporary data folder; nothing touches ~/Library/Application Support.
Run:  .venv/bin/python emu/test_platform.py
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import mpemu
import launcher

GAME = os.path.join(os.path.dirname(__file__), "..", "Max Payne")
K, A = "KERNEL32.DLL", "ADVAPI32.DLL"
HKCU = 0x80000001


def fresh(data):
    e = mpemu.Emu(GAME)
    e.data_dir = data
    return e


def api(e, dll, name, *args):
    return e.call(e.stub_for(dll, name), *args) & 0xFFFFFFFF


def cstr(e, s):
    p = e.alloc(len(s) + 1)
    e.wr(p, s.encode("latin1") + b"\0")
    return p


def reg_set(e, key, name, value):
    ph = e.alloc(4)
    assert api(e, A, "RegCreateKeyExA", HKCU, cstr(e, key), 0, 0, 0, 0xF003F, 0, ph, 0) == 0
    h = e.rd32(ph)
    if isinstance(value, int):
        data, typ = struct.pack("<I", value), mpemu.REG_DWORD
    else:
        data, typ = value.encode("latin1") + b"\0", mpemu.REG_SZ
    buf = e.alloc(len(data))
    e.wr(buf, data)
    assert api(e, A, "RegSetValueExA", h, cstr(e, name), 0, typ, buf, len(data)) == 0
    api(e, A, "RegCloseKey", h)


def reg_get(e, key, name):
    ph = e.alloc(4)
    if api(e, A, "RegOpenKeyExA", HKCU, cstr(e, key), 0, 0x20019, ph):
        return None
    h = e.rd32(ph)
    pt, pd, pc = e.alloc(4), e.alloc(256), e.alloc(4)
    e.wr32(pc, 256)
    r = api(e, A, "RegQueryValueExA", h, cstr(e, name), 0, pt, pd, pc)
    api(e, A, "RegCloseKey", h)
    if r:
        return None
    data = e.rd(pd, e.rd32(pc))
    return struct.unpack("<I", data)[0] if e.rd32(pt) == mpemu.REG_DWORD else data.rstrip(b"\0").decode("latin1")


def test_registry_persists(tmp):
    key = "Software\\Remedy Entertainment\\Save Game"
    e = fresh(tmp)
    reg_set(e, key, "Last Saved Game Filename", "C:\\My Documents\\Max Payne Savegames\\savegame003.mps")
    reg_set(e, "Software\\Remedy Entertainment\\Audio Settings", "Music Volume", 4321)
    e2 = fresh(tmp)                                                  # a new run reads what the last one wrote
    assert reg_get(e2, key, "last saved game filename") == "C:\\My Documents\\Max Payne Savegames\\savegame003.mps"
    assert reg_get(e2, "software\\remedy entertainment\\audio settings", "Music Volume") == 4321
    # delete a value, then the (now empty, subkey-less) key; both survive a restart
    ph = e2.alloc(4)
    api(e2, A, "RegOpenKeyExA", HKCU, cstr(e2, key), 0, 0, ph)
    assert api(e2, A, "RegDeleteValueA", e2.rd32(ph), cstr(e2, "Last Saved Game Filename")) == 0
    assert api(e2, A, "RegDeleteValueA", e2.rd32(ph), cstr(e2, "Last Saved Game Filename")) == mpemu.ERROR_FILE_NOT_FOUND
    assert api(e2, A, "RegDeleteKeyA", HKCU, cstr(e2, "Software\\Remedy Entertainment")) == 5   # has subkeys
    assert api(e2, A, "RegDeleteKeyA", HKCU, cstr(e2, key)) == 0
    e3 = fresh(tmp)
    assert reg_get(e3, key, "Last Saved Game Filename") is None
    assert reg_get(e3, "Software\\Remedy Entertainment\\Audio Settings", "Music Volume") == 4321
    print("ok  registry: values persist across runs; delete value / key (refused with subkeys)")


def test_registry_seed_and_overrides(tmp):
    VS = "HKCU\\Software\\Remedy Entertainment\\Video Settings"
    e = fresh(tmp)
    e.registry_seed = {(VS, "Display Width"): 1920, (VS, "Driver"): "x"}
    assert reg_get(e, "Software\\Remedy Entertainment\\Video Settings", "Display Width") == 1920
    reg_set(e, "Software\\Remedy Entertainment\\Video Settings", "Display Width", 1280)   # the game saves a choice
    e2 = fresh(tmp)
    e2.registry_seed = {(VS, "Display Width"): 1920}                  # a seed never replaces a stored value
    assert reg_get(e2, "Software\\Remedy Entertainment\\Video Settings", "Display Width") == 1280
    e3 = fresh(tmp)
    e3.registry_overrides = {(VS, "Display Width"): 800}             # an override (launcher option) does
    assert reg_get(e3, "Software\\Remedy Entertainment\\Video Settings", "Display Width") == 800
    assert reg_get(fresh(tmp), "Software\\Remedy Entertainment\\Video Settings", "Display Width") == 800
    print("ok  registry: seeds fill missing values only, overrides replace and persist")


def test_registry_handles_not_reused(tmp):
    e = fresh(tmp)
    ph = e.alloc(4)
    hs = []
    for k in ("Software\\A", "Software\\B"):
        api(e, A, "RegCreateKeyExA", HKCU, cstr(e, k), 0, 0, 0, 0, 0, ph, 0)
        hs.append(e.rd32(ph))
    api(e, A, "RegCloseKey", hs[0])
    api(e, A, "RegCreateKeyExA", HKCU, cstr(e, "Software\\C"), 0, 0, 0, 0, 0, ph, 0)
    assert e.rd32(ph) not in hs, "a new key got the handle of a key that is still open"
    print("ok  registry: handles of closed keys are not handed out again while others are open")


def write_file(e, path, data):
    h = api(e, K, "CreateFileA", cstr(e, path), 0x40000000, 0, 0, 2, 0x80, 0)   # GENERIC_WRITE, CREATE_ALWAYS
    assert h != 0xFFFFFFFF, path
    buf, pn = e.alloc(len(data)), e.alloc(4)
    e.wr(buf, data)
    assert api(e, K, "WriteFile", h, buf, len(data), pn, 0) == 1 and e.rd32(pn) == len(data)
    api(e, K, "CloseHandle", h)


def read_file(e, path):
    h = api(e, K, "CreateFileA", cstr(e, path), 0x80000000, 1, 0, 3, 0x80, 0)   # GENERIC_READ, OPEN_EXISTING
    if h == 0xFFFFFFFF:
        return None
    buf, pn = e.alloc(65536), e.alloc(4)
    api(e, K, "ReadFile", h, buf, 65536, pn, 0)
    api(e, K, "CloseHandle", h)
    return e.rd(buf, e.rd32(pn))


def find_names(e, pattern):
    p = e.alloc(320)
    h = api(e, K, "FindFirstFileA", cstr(e, pattern), p)
    names = []
    while h != 0xFFFFFFFF:
        names.append(e.cstr(p + 44))
        if not api(e, K, "FindNextFileA", h, p):
            break
    api(e, K, "FindClose", h)
    return [n for n in names if n not in (".", "..")]


def test_shell_folder_and_saved_games(tmp):
    e = fresh(tmp)
    sh = api(e, K, "LoadLibraryA", cstr(e, "shell32.dll"))
    assert sh
    fn = api(e, K, "GetProcAddress", sh, cstr(e, "SHGetSpecialFolderPathA"))
    assert fn
    buf = e.alloc(260)
    assert e.call(fn, 0, buf, 5, 1) & 0xFFFFFFFF == 1                   # CSIDL_PERSONAL, create: as the exe asks
    docs = e.cstr(buf)
    assert docs == "C:\\My Documents"
    assert os.path.isdir(os.path.join(tmp, "C", "My Documents"))
    assert e.call(fn, 0, buf, 0x99, 0) & 0xFFFFFFFF == 0                # unknown folder
    # the game's saved-game folder and files land in the per-user data, readable and listable by the game
    folder = docs + "\\Max Payne Savegames"
    assert api(e, K, "CreateDirectoryA", cstr(e, folder), 0) == 1
    write_file(e, folder + "\\savegame000.mps", b"MPSAVE" * 100)
    write_file(e, folder + "\\savegame001.mps", b"second")
    host = os.path.join(tmp, "C", "My Documents", "Max Payne Savegames", "savegame000.mps")
    assert open(host, "rb").read() == b"MPSAVE" * 100
    assert read_file(e, folder.upper() + "\\SAVEGAME000.MPS") == b"MPSAVE" * 100     # case-insensitive
    assert sorted(find_names(e, folder + "\\savegame*.mps")) == ["savegame000.mps", "savegame001.mps"]
    assert fresh(tmp) and read_file(fresh(tmp), folder + "\\savegame001.mps") == b"second"   # next run
    print("ok  SHGetSpecialFolderPathA(CSIDL_PERSONAL); saved games in <data>/C/My Documents, case-insensitive")


def test_game_folder_overlay(tmp):
    e = fresh(tmp)
    note = "C:\\MaxPayne\\savegames\\Where are my saved games.txt"
    original = read_file(e, note)
    assert original and original.startswith(b"Max Payne saved games")
    # a write into the game folder goes to the overlay; the shipped file is untouched
    h = api(e, K, "CreateFileA", cstr(e, "savegames\\Where are my saved games.txt"), 0xC0000000, 0, 0, 3, 0x80, 0)
    buf, pn = e.alloc(8), e.alloc(4)
    e.wr(buf, b"CHANGED!")
    api(e, K, "WriteFile", h, buf, 8, pn, 0)
    api(e, K, "CloseHandle", h)
    assert open(os.path.join(GAME, "savegames", "Where are my saved games.txt"), "rb").read() == original
    assert read_file(e, note)[:8] == b"CHANGED!" and read_file(e, note)[8:] == original[8:]   # copy-on-write
    assert os.path.isfile(os.path.join(tmp, "game", "savegames", "Where are my saved games.txt"))
    write_file(e, "C:\\MaxPayne\\savegames\\new.txt", b"x")
    assert "new.txt" in find_names(e, "savegames\\*.*") and "Where are my saved games.txt" in find_names(e, "savegames\\*.*")
    # other drive paths are per-user too, never the game folder
    write_file(e, "C:\\Temp\\a.txt", b"t")
    assert os.path.isfile(os.path.join(tmp, "C", "Temp", "a.txt"))
    assert not os.path.exists(os.path.join(GAME, "Temp"))
    write_file(e, "\\Rooted\\b.txt", b"r")                              # rooted path: on C:
    assert os.path.isfile(os.path.join(tmp, "C", "Rooted", "b.txt"))
    print("ok  game folder: writes go to the overlay (copy-on-write), listings merge; other C: paths per-user")


def test_launcher(tmp):
    m = mpemu
    e = fresh(tmp)
    host = launcher.configure(m, e, ["run_init.py", "Max Payne", "--resolution", "1280x720", "--fullscreen",
                                     "--set", "Advanced Settings/Fogging=0", "--set", "Video Settings/Note=hi"])
    assert host == {"fullscreen": True, "game_mode": "fullscreen"}
    assert e.command_line.endswith("-nodialog")
    assert launcher.resolution(m, e) == (1280, 720)
    assert reg_get(e, "Software\\Remedy Entertainment\\Advanced Settings", "Fogging") == 0
    assert reg_get(e, "Software\\Remedy Entertainment\\Video Settings", "Note") == "hi"
    assert reg_get(e, "Software\\Remedy Entertainment\\Video Settings", "Driver").startswith("Apple GPU")
    # the next run, with no options, keeps all of it
    e2 = fresh(tmp)
    host = launcher.configure(m, e2, ["run_init.py", "Max Payne"])
    assert host["fullscreen"] and launcher.resolution(m, e2) == (1280, 720)
    assert launcher.configure(m, fresh(tmp), ["x", "--game-mode", "windowed"])["game_mode"] == "windowed"
    e3 = fresh(tmp)
    launcher.configure(m, e3, ["x", "--windowed"])
    assert e3.command_line.endswith("-nodialog -window") and not e3.host_settings["fullscreen"]
    for bad in (["--resolution", "1234x567"], ["--resolution", "big"], ["--set", "NoSection=1"],
                ["--game-mode", "tiny"]):
        try:
            launcher.configure(m, fresh(tmp), ["x"] + bad)
        except SystemExit:
            pass
        else:
            raise AssertionError("accepted %r" % bad)
    print("ok  launcher: resolution, fullscreen, game mode, --set; remembered; bad options refused")


if __name__ == "__main__":
    for t in (test_registry_persists, test_registry_seed_and_overrides, test_registry_handles_not_reused,
              test_shell_folder_and_saved_games, test_game_folder_overlay, test_launcher):
        with tempfile.TemporaryDirectory() as tmp:
            t(tmp)
    print("all platform tests passed")
