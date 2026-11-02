"""Native launcher options: what the game's startup dialog (CMaxPayneStartupDialog, MaxPayneAdvancedDialog) set on
Windows, as command-line options that persist between runs.

The dialog never runs: the game skips it when it finds complete saved video settings and is started with -nodialog
(maxpayne.exe+0x407190, see docs/m2-progress.md). Everything the dialog would store lives in the registry under
HKCU\\Software\\Remedy Entertainment (mpemu keeps it in <data>/registry.json). The launcher:
  - seeds the values the dialog must have written (Video Settings: driver, resolution, depth) when they are missing;
  - applies options the player gives (--resolution, --set) as registry overrides, so they persist like a dialog OK;
  - keeps host-only choices (Mac window or fullscreen, the game's display mode) in <data>/launcher.json.

Options (emu/run_init.py passes its argv here):
  --resolution WxH          display mode the game runs at (one of the modes the Direct3D layer offers)
  --fullscreen / --windowed show the game fullscreen on the Mac, or in a window (remembered)
  --game-mode fullscreen|windowed
                            the game's own display mode; "windowed" passes -window (debugging; remembered)
  --set "Section/Value=N"   any setting the dialogs store, e.g. "Advanced Settings/Level Texture Detail=2"
                            (numbers are stored as DWORDs, anything else as a string)
  --settings                print the current settings and exit
"""
import json
import os
import struct

VS = "HKCU\\Software\\Remedy Entertainment\\Video Settings"
ROOT_KEY = "HKCU\\Software\\Remedy Entertainment"
# From the real entry point (run_init.py --real-entry) MFC's AfxWinInit sets the profile name to the app title
# (AFX_IDS_APP_TITLE, "Max Payne"), so the game keeps its settings one key down, as on Windows. Without AfxWinInit
# (run_init calls InitInstance itself) the profile name is empty and they are directly under ROOT_KEY.
APP_KEY = ROOT_KEY + "\\Max Payne"
DEFAULTS = {"fullscreen": False, "game_mode": "fullscreen"}


def _arg(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def host_settings_path(m, e):
    return os.path.join(m.data_dir(e), "launcher.json")


def load_host_settings(m, e):
    try:
        s = json.load(open(host_settings_path(m, e)))
    except (OSError, ValueError):
        s = {}
    return dict(DEFAULTS, **{k: v for k, v in s.items() if k in DEFAULTS})


def save_host_settings(m, e, s):
    tmp = host_settings_path(m, e) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1)
    os.replace(tmp, host_settings_path(m, e))


def display_modes(m):
    import d3d8
    return d3d8.display_modes(m)


def root_key(e):
    """The key the game keeps its settings under in this run (see APP_KEY)."""
    return getattr(e, "reg_root", ROOT_KEY)


def _copy_classic_settings(m, e):
    """The first --real-entry run: copy the settings stored under ROOT_KEY (runs without AfxWinInit) to APP_KEY, so
    the resolution, key bindings and options carry over. The originals stay for runs without --real-entry."""
    st = m._regstore(e)
    old, new = ROOT_KEY.lower(), APP_KEY.lower()
    if any(k == new or k.startswith(new + "\\") for k in st):
        return
    for k in [k for k in st if k.startswith(old + "\\")]:
        m._reg_key(st, new + k[len(old):]).update(st[k])
    m._reg_save(e)


def configure(m, e, argv):
    """Apply launcher options to emulator e (before boot runs any guest code). Returns the host settings."""
    import d3d8
    e.reg_root = APP_KEY if "--real-entry" in argv else ROOT_KEY
    if e.reg_root == APP_KEY:
        _copy_classic_settings(m, e)
    VS = root_key(e) + "\\Video Settings"
    host = load_host_settings(m, e)
    if "--fullscreen" in argv:
        host["fullscreen"] = True
    if "--windowed" in argv:
        host["fullscreen"] = False
    gm = _arg(argv, "--game-mode")
    if gm:
        if gm not in ("fullscreen", "windowed"):
            raise SystemExit("--game-mode must be fullscreen or windowed")
        host["game_mode"] = gm
    save_host_settings(m, e, host)

    # What the startup dialog must have stored for the game to skip it (seeded only when missing).
    e.registry_seed = {
        (VS, "Driver"): d3d8.ADAPTER_DESCRIPTION,   # the engine names drivers after the D3D adapter description
        (VS, "Display Width"): m.SCREEN[0],
        (VS, "Display Height"): m.SCREEN[1],
        (VS, "Display Bits Per Pixel"): 32,
        (VS, "CPU Driver"): 0,
        (VS, "HW Acceleration Level"): 2,
    }
    over = {}
    res = _arg(argv, "--resolution")
    if res:
        try:
            w, h = (int(x) for x in res.lower().split("x"))
        except ValueError:
            raise SystemExit("--resolution takes WxH, e.g. 1280x720")
        if (w, h) not in display_modes(m):
            raise SystemExit("--resolution %dx%d is not offered; modes: %s" % (
                w, h, ", ".join("%dx%d" % x for x in display_modes(m))))
        over[(VS, "Display Width")], over[(VS, "Display Height")] = w, h
    for i, a in enumerate(argv):
        if a == "--set":
            item = argv[i + 1]
            key, _, val = item.partition("=")
            section, _, name = key.rpartition("/")
            if not section or not name or not _:
                raise SystemExit('--set takes "Section/Value=N", e.g. "Advanced Settings/Fogging=1"')
            over[(root_key(e) + "\\" + section, name)] =int(val, 0) if val.lstrip("-").isdigit() or val.startswith("0x") else val
    e.registry_overrides = over
    if hasattr(e, "registry"):                # loaded already (_copy_classic_settings)
        m._reg_apply(e)
    e.command_line = '"C:\\MaxPayne\\MaxPayne.exe" -nodialog' + (" -window" if host["game_mode"] == "windowed" else "")
    e.host_settings = host
    return host


def resolution(m, e):
    """The display mode the game will run at (from the registry, as the game reads it)."""
    st = m._regstore(e)
    vs = st.get((root_key(e) + "\\Video Settings").lower(), {})
    w = vs.get("display width", (4, struct.pack("<I", m.SCREEN[0])))[1]
    h = vs.get("display height", (4, struct.pack("<I", m.SCREEN[1])))[1]
    return struct.unpack("<I", w[:4])[0], struct.unpack("<I", h[:4])[0]


def print_settings(m, e):
    st = m._regstore(e)
    print("Settings in %s" % m.data_dir(e))
    print("  host: %s" % ", ".join("%s=%s" % kv for kv in sorted(e.host_settings.items())))
    print("  display modes offered: %s" % ", ".join("%dx%d" % x for x in display_modes(m)))
    prefix = root_key(e).lower() + "\\"
    other = APP_KEY.lower() + "\\" if root_key(e) == ROOT_KEY else None     # the --real-entry settings
    for key in sorted(k for k in st if k.startswith(prefix) and not (other and (k + "\\").startswith(other))):
        values = st[key]
        if not values or key.endswith("input settings"):
            continue
        print("  [%s]" % key[len(prefix):])
        for name, (typ, data) in sorted(values.items()):
            if typ == m.REG_DWORD and len(data) == 4:
                v = struct.unpack("<i", data)[0]
            elif typ in (m.REG_SZ, m.REG_EXPAND_SZ):
                v = repr(data.rstrip(b"\0").decode("latin1"))
            else:
                v = data.hex()
            print("    %-28s %s" % (name, v))
    n = len(st.get(prefix + "input settings", {}))
    if n:
        print("  [input settings] %d values (key bindings)" % n)
