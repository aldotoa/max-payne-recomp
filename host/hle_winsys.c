/* The window manager for the native host (E6): a port of emu/winsys.py. A window table and class registry,
 * CreateWindowExA with MFC's CBT hook (WH_CBT / HCBT_CREATEWND) and WM_NCCREATE / WM_CREATE / WM_SIZE / WM_MOVE, a
 * native DefWindowProc, SendMessage / PostMessage / a message queue for PeekMessage, Get/SetWindowLong, geometry,
 * focus and activation. Window procedures and hooks are called directly (host_guest_call): the Python handlers that
 * do so are coroutines, flagged HLE_CORO here so the API log has the same "[coroutine]" lines.
 * Key messages come from the DINPUT input state (hle_dinput.c), which also hears of the app losing focus. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host.h"

#define U "USER32.DLL"
#define H(name) static uint32_t name(CPU *c, const uint32_t *a)
#define UNUSED (void)c, (void)a

#define WS_CHILD 0x40000000u
#define WS_VISIBLE 0x10000000u
#define WS_CAPTION 0x00C00000u
#define CW_USEDEFAULT 0x80000000u
#define HCBT_CREATEWND 3
#define WH_KEYBOARD 2
#define WH_CBT 5
#define HC_ACTION 0
#define HC_NOREMOVE 3
#define GUEST_THREAD_ID 1
#define DESKTOP 0x1001u
#define LEGACY_ACTIVE 0x1000u

enum {
    WM_CREATE = 0x1, WM_DESTROY = 0x2, WM_MOVE = 0x3, WM_SIZE = 0x5, WM_ACTIVATE = 0x6, WM_SETFOCUS = 0x7,
    WM_KILLFOCUS = 0x8, WM_SETTEXT = 0xC, WM_GETTEXT = 0xD, WM_GETTEXTLENGTH = 0xE, WM_CLOSE = 0x10, WM_QUIT = 0x12,
    WM_ERASEBKGND = 0x14, WM_SHOWWINDOW = 0x18, WM_ACTIVATEAPP = 0x1C, WM_NCCREATE = 0x81, WM_NCDESTROY = 0x82,
    WM_NCHITTEST = 0x84, WM_NCACTIVATE = 0x86, WM_KEYDOWN = 0x100, WM_KEYUP = 0x101, WM_CHAR = 0x102,
    WM_SYSKEYDOWN = 0x104, WM_SYSKEYUP = 0x105, WM_SYSCHAR = 0x106,
};

static const uint32_t SCREEN[2] = {HOST_SCREEN_W, HOST_SCREEN_H};

typedef struct {
    char name[256];
    uint32_t wndproc, style, cbwndextra, hinst, hicon, hcursor, hbr, menu, atom;
} Cls;

typedef struct { int32_t key; uint32_t val; } Extra;
typedef struct { char name[256]; uint32_t val; } Prop;

typedef struct {
    uint32_t hwnd;
    char cls[256];
    uint32_t wndproc, style, exstyle, parent;
    int32_t x, y, w, h;
    uint32_t hinst, id, userdata;
    char *text;
    int visible, enabled;
    Extra *extra;
    uint32_t nextra;
    Prop *props;
    uint32_t nprops;
} Win;

typedef struct { uint32_t h, msg, w, l; int hooked; } Msg;
typedef struct { uint32_t handle, hid, proc; } Hook;

/* WinSys: made on first use, as S(e) */
static struct {
    int made;
    Win **windows;                  /* in creation order (Python's dict order) */
    uint32_t nwin, capwin;
    Cls *classes;
    uint32_t ncls, capcls;
    char (*atoms)[256];             /* atom 0xC000 + i */
    uint32_t natoms, capatoms;
    Msg *queue;
    uint32_t nq, capq;
    Hook *hooks;
    uint32_t nhooks, caphooks;
    uint32_t next_hwnd, next_hook, focus, active, capture, defproc;
    int app_active, pending_app_active;    /* pending: -1 none */
} W;

#define GROW(arr, n, cap)                                                                                             \
    do {                                                                                                              \
        if ((n) == (cap)) {                                                                                           \
            (cap) = (cap) ? 2 * (cap) : 16;                                                                           \
            (arr) = realloc((arr), (cap) * sizeof *(arr));                                                            \
        }                                                                                                             \
    } while (0)

/* str.upper of a latin-1 string (the letters a-z and U+00E0-U+00FE but U+00F7) */
static void upper(char *s)
{
    for (unsigned char *p = (unsigned char *)s; *p; p++)
        if ((*p >= 'a' && *p <= 'z') || (*p >= 0xE0 && *p <= 0xFE && *p != 0xF7))
            *p = (unsigned char)(*p - 0x20);
}

static uint32_t atom_for(const char *name)
{
    char up[256];
    snprintf(up, sizeof up, "%s", name);
    upper(up);
    for (uint32_t i = 0; i < W.natoms; i++)
        if (strcmp(W.atoms[i], up) == 0)
            return 0xC000 + i;
    GROW(W.atoms, W.natoms, W.capatoms);
    snprintf(W.atoms[W.natoms], sizeof W.atoms[0], "%s", up);
    return 0xC000 + W.natoms++;
}

static Cls *class_get(const char *name)
{
    for (uint32_t i = 0; i < W.ncls; i++)
        if (strcmp(W.classes[i].name, name) == 0)
            return &W.classes[i];
    return NULL;
}

static Cls *class_put(const char *name)
{
    Cls *k = class_get(name);
    if (!k) {
        GROW(W.classes, W.ncls, W.capcls);
        k = &W.classes[W.ncls++];
    }
    memset(k, 0, sizeof *k);
    snprintf(k->name, sizeof k->name, "%s", name);
    return k;
}

static void S(void)
{
    if (W.made)
        return;
    W.made = 1;
    W.next_hwnd = 0x10010;
    W.next_hook = 0x4000;
    W.pending_app_active = -1;
    W.defproc = host_stub_for(U, "DefWindowProcA");
    static const char *const BUILTIN[] = {"BUTTON", "STATIC", "EDIT", "COMBOBOX", "LISTBOX", "SCROLLBAR", "#32770",
                                          "MDICLIENT"};
    for (size_t i = 0; i < sizeof BUILTIN / sizeof *BUILTIN; i++) {
        Cls *k = class_put(BUILTIN[i]);
        k->wndproc = W.defproc;
        k->atom = atom_for(BUILTIN[i]);
    }
}

/* class_name: an atom (below 0x10000) by its name, else the string upper-cased */
static void class_name(uint32_t p, char *out, size_t cap)
{
    if (p < 0x10000) {
        if (p >= 0xC000 && p - 0xC000 < W.natoms)
            snprintf(out, cap, "%s", W.atoms[p - 0xC000]);
        else
            snprintf(out, cap, "#%u", p);
        return;
    }
    host_cstr(p, out, cap);
    upper(out);
}

static Win *getwin(uint32_t hwnd)
{
    for (uint32_t i = 0; i < W.nwin; i++)
        if (W.windows[i]->hwnd == hwnd)
            return W.windows[i];
    return NULL;
}

static void win_free(Win *w)
{
    free(w->text);
    free(w->extra);
    free(w->props);
    free(w);
}

static void win_pop(uint32_t hwnd)
{
    for (uint32_t i = 0; i < W.nwin; i++)
        if (W.windows[i]->hwnd == hwnd) {
            win_free(W.windows[i]);
            memmove(&W.windows[i], &W.windows[i + 1], (W.nwin - i - 1) * sizeof *W.windows);
            W.nwin--;
            return;
        }
}

static void set_text(Win *w, uint32_t p)
{
    char s[4100] = "";
    if (p)
        host_cstr(p, s, sizeof s);
    free(w->text);
    w->text = strdup(s);
}

static void queue_insert(uint32_t at, uint32_t h, uint32_t msg, uint32_t w, uint32_t l)
{
    GROW(W.queue, W.nq, W.capq);
    memmove(&W.queue[at + 1], &W.queue[at], (W.nq - at) * sizeof *W.queue);
    W.queue[at] = (Msg){h, msg, w, l, 0};
    W.nq++;
}

static void queue_pop(uint32_t i)
{
    memmove(&W.queue[i], &W.queue[i + 1], (W.nq - i - 1) * sizeof *W.queue);
    W.nq--;
}

static uint32_t call4(CPU *c, uint32_t proc, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
    uint32_t args[4] = {a0, a1, a2, a3};
    return host_guest_call(c, proc, 4, args);
}

/* ---------------------------------------------------------------- message delivery */
static uint32_t destroy(CPU *c, uint32_t hwnd);

/* the native DefWindowProc */
static uint32_t defproc(CPU *c, Win *win, uint32_t msg, uint32_t w, uint32_t l)
{
    switch (msg) {
    case WM_NCCREATE:
    case WM_ERASEBKGND:
    case WM_NCHITTEST:                  /* HTCLIENT */
        return 1;
    case WM_SETTEXT:
        set_text(win, l);
        return 1;
    case WM_GETTEXT: {
        uint32_t n = (uint32_t)strlen(win->text);
        if (w == 0)
            return 0;
        if (n > w - 1)
            n = w - 1;
        memcpy(gptr(l), win->text, n);
        gptr(l)[n] = 0;
        return n;
    }
    case WM_GETTEXTLENGTH:
        return (uint32_t)strlen(win->text);
    case WM_CLOSE:
        destroy(c, win->hwnd);
        return 0;
    }
    return 0;
}

static uint32_t send(CPU *c, uint32_t hwnd, uint32_t msg, uint32_t w, uint32_t l)
{
    Win *win = getwin(hwnd);
    if (!win)
        return 0;
    if (win->wndproc == W.defproc)
        return defproc(c, win, msg, w, l);
    return call4(c, win->wndproc, hwnd, msg, w, l);
}

static Win *top_level(uint32_t hwnd)
{
    Win *win = getwin(hwnd);
    while (win && (win->style & WS_CHILD) && getwin(win->parent))
        win = getwin(win->parent);
    return win;
}

/* WM_ACTIVATEAPP to every top-level window when the app gains or loses activation */
static void set_app_active(CPU *c, int active)
{
    if (W.app_active == !!active)
        return;
    W.app_active = !!active;
    uint32_t n = W.nwin, *hs = malloc((n + 1) * sizeof *hs), *st = malloc((n + 1) * sizeof *st);
    for (uint32_t i = 0; i < n; i++)
        hs[i] = W.windows[i]->hwnd, st[i] = W.windows[i]->style;
    for (uint32_t i = 0; i < n; i++)
        if (!(st[i] & WS_CHILD))
            send(c, hs[i], WM_ACTIVATEAPP, active ? 1 : 0, GUEST_THREAD_ID);
    free(hs);
    free(st);
}

static uint32_t set_focus(CPU *c, uint32_t hwnd)
{
    uint32_t old = W.focus;
    if (old == hwnd)
        return old;
    W.focus = hwnd;
    if (getwin(old))
        send(c, old, WM_KILLFOCUS, hwnd, 0);
    if (getwin(hwnd))
        send(c, hwnd, WM_SETFOCUS, old, 0);
    return old;
}

/* make a top-level window the active one, with the message sequence Windows uses (WM_ACTIVATEAPP, WM_NCACTIVATE,
 * WM_ACTIVATE, then focus). The game's main window only renders after WM_ACTIVATEAPP(TRUE). */
static uint32_t activate(CPU *c, uint32_t hwnd)
{
    Win *top = top_level(hwnd);
    if (!top)
        return W.active;
    uint32_t th = top->hwnd, old = W.active;
    if (old == th && W.app_active)
        return old;
    if (getwin(old) && old != th) {
        send(c, old, WM_NCACTIVATE, 0, 0);
        send(c, old, WM_ACTIVATE, 0, th);
    }
    set_app_active(c, 1);
    W.active = th;
    send(c, th, WM_NCACTIVATE, 1, 0);
    send(c, th, WM_ACTIVATE, 1, old);   /* WA_ACTIVE */
    Win *ft = top_level(W.focus);
    if (!ft || ft->hwnd != th)
        set_focus(c, th);
    return old;
}

/* the app lost activation (the host window lost focus) */
static void deactivate_app(CPU *c)
{
    if (getwin(W.active)) {
        send(c, W.active, WM_NCACTIVATE, 0, 0);
        send(c, W.active, WM_ACTIVATE, 0, 0);
    }
    set_app_active(c, 0);
    if (getwin(W.focus))
        send(c, W.focus, WM_KILLFOCUS, 0, 0);
    W.active = W.focus = 0;
    host_focus_lost();
}

static uint32_t destroy(CPU *c, uint32_t hwnd)
{
    Win *win = getwin(hwnd);
    if (!win)
        return 0;
    win->visible = 0;
    send(c, hwnd, WM_DESTROY, 0, 0);
    send(c, hwnd, WM_NCDESTROY, 0, 0);
    win_pop(hwnd);
    if (W.focus == hwnd)
        W.focus = 0;
    if (W.active == hwnd)
        W.active = 0;
    return 1;
}

/* ---------------------------------------------------------------- host side */
void host_post_quit(uint32_t code)
{
    S();
    queue_insert(W.nq, 0, WM_QUIT, code, 0);
}

void host_set_app_active(int active)
{
    S();
    W.pending_app_active = !!active;
}

/* ---------------------------------------------------------------- classes */
H(RegisterClassA)
{
    UNUSED;
    S();
    uint32_t v[10];
    memcpy(v, gptr(a[0]), 40);
    char name[256];
    class_name(v[9], name, sizeof name);
    uint32_t atom = atom_for(name);
    Cls *k = class_put(name);
    k->style = v[0], k->wndproc = v[1], k->cbwndextra = v[3], k->hinst = v[4], k->hicon = v[5], k->hcursor = v[6];
    k->hbr = v[7], k->menu = v[8], k->atom = atom;
    return atom;
}

H(UnregisterClassA)
{
    UNUSED;
    S();
    char name[256];
    class_name(a[0], name, sizeof name);
    Cls *k = class_get(name);
    if (!k)
        return 0;
    uint32_t i = (uint32_t)(k - W.classes);
    memmove(&W.classes[i], &W.classes[i + 1], (W.ncls - i - 1) * sizeof *W.classes);
    W.ncls--;
    return 1;
}

H(GetClassInfoA)
{
    UNUSED;
    S();
    char name[256];
    class_name(a[1], name, sizeof name);
    Cls *k = class_get(name);
    if (!k) {
        host_set_last_error(1411);      /* ERROR_CLASS_DOES_NOT_EXIST */
        return 0;
    }
    uint32_t v[10] = {k->style, k->wndproc, 0, k->cbwndextra, k->hinst, k->hicon, k->hcursor, k->hbr, k->menu, a[1]};
    memcpy(gptr(a[2]), v, 40);
    return k->atom;
}

static uint32_t copy_out(const char *s, uint32_t buf, uint32_t n)
{
    if (n == 0)
        return 0;
    uint32_t k = (uint32_t)strlen(s);
    if (k > n - 1)
        k = n - 1;
    memcpy(gptr(buf), s, k);
    gptr(buf)[k] = 0;
    return k;
}

H(GetClassNameA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    return copy_out(w ? w->cls : "", a[1], a[2]);
}

H(GetClassLongA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    Cls *k = w ? class_get(w->cls) : NULL;
    if (!k)
        return 0;
    switch ((int32_t)a[1]) {
    case -24: return k->wndproc;
    case -10: return k->hbr;
    case -12: return k->hcursor;
    case -14: return k->hicon;
    case -26: return k->style;
    case -8: return k->menu;
    case -18: return k->cbwndextra;
    }
    return 0;
}

/* ---------------------------------------------------------------- hooks */
H(SetWindowsHookExA)
{
    UNUSED;
    S();
    W.next_hook += 4;
    GROW(W.hooks, W.nhooks, W.caphooks);
    W.hooks[W.nhooks++] = (Hook){W.next_hook, a[0], a[1]};
    return W.next_hook;
}

H(UnhookWindowsHookEx)
{
    UNUSED;
    S();
    uint32_t k = 0, before = W.nhooks;
    for (uint32_t i = 0; i < W.nhooks; i++)
        if (W.hooks[i].handle != a[0])
            W.hooks[k++] = W.hooks[i];
    W.nhooks = k;
    return k != before;
}

H(Return0) { UNUSED; return 0; }
H(Return1) { UNUSED; return 1; }

/* a copy of the hook list (a hook may unhook itself) */
static Hook *hooks_copy(uint32_t *n)
{
    *n = W.nhooks;
    Hook *h = malloc((W.nhooks + 1) * sizeof *h);
    memcpy(h, W.hooks, W.nhooks * sizeof *h);
    return h;
}

/* ---------------------------------------------------------------- window creation */
H(CreateWindowExA)
{
    S();
    uint32_t ex = a[0], clsp = a[1], title = a[2], style = a[3], x = a[4], y = a[5], w = a[6], h = a[7];
    uint32_t parent = a[8], menu = a[9], hinst = a[10], param = a[11];
    char name[256];
    class_name(clsp, name, sizeof name);
    Cls *k = class_get(name);
    if (!k) {
        host_set_last_error(1407);      /* ERROR_CANNOT_FIND_WND_CLASS */
        return 0;
    }
    if (x == CW_USEDEFAULT)
        x = 0;
    if (y == CW_USEDEFAULT)
        y = 0;
    if (w == CW_USEDEFAULT)
        w = SCREEN[0] / 2;
    if (h == CW_USEDEFAULT)
        h = SCREEN[1] / 2;
    uint32_t hwnd = W.next_hwnd;
    W.next_hwnd += 4;
    Win *win = calloc(1, sizeof *win);
    win->hwnd = hwnd;
    snprintf(win->cls, sizeof win->cls, "%s", k->name);
    win->wndproc = k->wndproc, win->style = style, win->exstyle = ex, win->parent = parent;
    win->x = (int32_t)x, win->y = (int32_t)y, win->w = (int32_t)w, win->h = (int32_t)h;
    win->hinst = hinst, win->id = (style & WS_CHILD) ? menu : 0, win->enabled = 1;
    set_text(win, title);
    GROW(W.windows, W.nwin, W.capwin);
    W.windows[W.nwin++] = win;
    uint32_t cs = host_alloc(48);
    uint32_t v[12] = {param, hinst, menu, parent, h, w, y, x, style, title, clsp, ex};
    memcpy(gptr(cs), v, 48);
    uint32_t nh;
    Hook *hooks = hooks_copy(&nh);
    for (uint32_t i = 0; i < nh; i++) {     /* MFC subclasses the window from its CBT hook */
        if (hooks[i].hid != WH_CBT)
            continue;
        uint32_t cbt = host_alloc(8);
        uint32_t cv[2] = {cs, 0};
        memcpy(gptr(cbt), cv, 8);
        uint32_t args[3] = {HCBT_CREATEWND, hwnd, cbt};
        if (host_guest_call(c, hooks[i].proc, 3, args)) {   /* the hook vetoed the creation */
            win_pop(hwnd);
            free(hooks);
            return 0;
        }
    }
    free(hooks);
    if (send(c, hwnd, WM_NCCREATE, 0, cs) == 0) {
        win_pop(hwnd);
        return 0;
    }
    if (send(c, hwnd, WM_CREATE, 0, cs) == 0xFFFFFFFFu) {
        send(c, hwnd, WM_NCDESTROY, 0, 0);
        win_pop(hwnd);
        return 0;
    }
    send(c, hwnd, WM_SIZE, 0, ((h & 0xFFFF) << 16) | (w & 0xFFFF));
    send(c, hwnd, WM_MOVE, 0, ((y & 0xFFFF) << 16) | (x & 0xFFFF));
    if (style & WS_VISIBLE) {
        if ((win = getwin(hwnd)))
            win->visible = 1;
        send(c, hwnd, WM_SHOWWINDOW, 1, 0);
    }
    return hwnd;
}

H(DestroyWindow) { UNUSED; S(); return destroy(c, a[0]); }

H(DefWindowProcA)
{
    S();
    Win *w = getwin(a[0]);
    return w ? defproc(c, w, a[1], a[2], a[3]) : 0;
}

H(CallWindowProcA)
{
    S();
    Win *w = getwin(a[1]);
    if (a[0] == W.defproc && w)
        return defproc(c, w, a[2], a[3], a[4]);
    return call4(c, a[0], a[1], a[2], a[3], a[4]);
}

/* ---------------------------------------------------------------- messages */
H(SendMessageA) { S(); return send(c, a[0], a[1], a[2], a[3]); }

H(PostMessageA)
{
    UNUSED;
    S();
    queue_insert(W.nq, a[0], a[1], a[2], a[3]);
    return 1;
}

H(PostThreadMessageA)
{
    UNUSED;
    S();
    queue_insert(W.nq, 0, a[1], a[2], a[3]);
    return 1;
}

H(PostQuitMessage)
{
    UNUSED;
    S();
    queue_insert(W.nq, 0, WM_QUIT, a[0], 0);
    return 0;
}

/* what the host did since the last pump: focus changes (sent messages) and key presses from the DINPUT state
 * (posted WM_KEYDOWN/WM_KEYUP to the focus window, as Windows does) */
static void host_events(CPU *c)
{
    if (W.pending_app_active >= 0) {
        int want = W.pending_app_active;
        W.pending_app_active = -1;
        if (want && W.nwin) {
            for (uint32_t i = 0; i < W.nwin; i++)
                if (!(W.windows[i]->style & WS_CHILD) && W.windows[i]->visible) {
                    activate(c, W.windows[i]->hwnd);
                    break;
                }
        } else if (!want)
            deactivate_app(c);
    }
    HostKeyMsg k;
    while (host_key_msg(&k)) {
        uint32_t target = W.focus ? W.focus : W.active;
        if (!target)
            continue;                   /* no window has the keyboard focus: dropped, like Windows */
        int sys_key = k.alt || k.vk == 0x79;   /* Alt held, or F10 */
        uint32_t msg = sys_key ? (k.down ? WM_SYSKEYDOWN : WM_SYSKEYUP) : (k.down ? WM_KEYDOWN : WM_KEYUP);
        uint32_t l = 1 | (k.scan << 16) | (k.ext << 24) | ((k.alt ? 1u : 0u) << 29) | ((k.down ? 0u : 3u) << 30);
        queue_insert(W.nq, target, msg, k.vk, l);
    }
}

static int key_msg(uint32_t m) { return m == WM_KEYDOWN || m == WM_KEYUP || m == WM_SYSKEYDOWN || m == WM_SYSKEYUP; }

/* find a matching message; keyboard messages pass the WH_KEYBOARD hooks first (a hook that returns nonzero swallows
 * the message). Returns 1 and the message. */
static int pop_message(CPU *c, uint32_t pmsg, uint32_t hwnd_filter, uint32_t lo, uint32_t hi, int remove,
                       uint32_t *msg_out)
{
    host_events(c);
    uint32_t i = 0;
    while (i < W.nq) {
        Msg m = W.queue[i];
        if ((hwnd_filter && m.h != hwnd_filter) || ((lo || hi) && !(lo <= m.msg && m.msg <= hi))) {
            i++;
            continue;
        }
        if (key_msg(m.msg) && !m.hooked) {
            int swallowed = 0;
            uint32_t nh;
            Hook *hooks = hooks_copy(&nh);
            for (uint32_t j = 0; j < nh; j++)
                if (hooks[j].hid == WH_KEYBOARD) {
                    uint32_t args[3] = {remove ? HC_ACTION : HC_NOREMOVE, m.w, m.l};
                    swallowed |= host_guest_call(c, hooks[j].proc, 3, args) != 0;
                }
            free(hooks);
            if (swallowed) {
                queue_pop(i);
                continue;
            }
            if (!remove)                /* hooks already saw it: do not call them again */
                W.queue[i].hooked = 1;
        }
        if (remove)
            queue_pop(i);
        uint32_t v[7] = {m.h, m.msg, m.w, m.l, host_tick(), 0, 0};
        memcpy(gptr(pmsg), v, 28);
        *msg_out = m.msg;
        return 1;
    }
    return 0;
}

H(PeekMessageA)
{
    S();
    uint32_t msg;
    return (uint32_t)pop_message(c, a[0], a[1], a[2], a[3], a[4] & 1, &msg);
}

H(GetMessageA)
{
    S();
    uint32_t msg;
    if (!pop_message(c, a[0], a[1], a[2], a[3], 1, &msg))
        return 0;                       /* a real GetMessage would block; end the loop instead */
    return msg != WM_QUIT;
}

/* WM_KEYDOWN -> WM_CHAR (WM_SYSKEYDOWN -> WM_SYSCHAR), at the front of the queue */
H(TranslateMessage)
{
    UNUSED;
    S();
    uint32_t v[4];
    memcpy(v, gptr(a[0]), 16);
    if ((v[1] != WM_KEYDOWN && v[1] != WM_SYSKEYDOWN) || !host_input_made())
        return 0;
    int ch = host_char_for(((v[3] >> 16) & 0x7F) | ((v[3] & (1u << 24)) ? 0x80 : 0));
    if (ch < 0)
        return 0;
    queue_insert(0, v[0], v[1] == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, (uint32_t)ch, v[3]);
    return 1;
}

H(DispatchMessageA)
{
    S();
    uint32_t v[4];
    memcpy(v, gptr(a[0]), 16);
    return v[0] ? send(c, v[0], v[1], v[2], v[3]) : 0;
}

/* ---------------------------------------------------------------- window state */
H(IsWindow) { UNUSED; S(); return getwin(a[0]) || a[0] == DESKTOP || a[0] == LEGACY_ACTIVE; }

H(IsWindowVisible)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    return w && w->visible;
}

H(IsWindowEnabled)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    return !w || w->enabled;
}

H(EnableWindow)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    int was = !w->enabled;
    w->enabled = a[1] != 0;
    return (uint32_t)was;
}

H(ShowWindow)
{
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    uint32_t cmd = a[1], hwnd = a[0];
    int was = w->visible, child = (w->style & WS_CHILD) != 0;
    w->visible = cmd != 0;
    send(c, hwnd, WM_SHOWWINDOW, cmd ? 1 : 0, 0);
    if (cmd != 0 && cmd != 4 && cmd != 6 && cmd != 7 && cmd != 8 && !child)   /* every SW_SHOW* that activates */
        activate(c, hwnd);
    return (uint32_t)was;
}

H(GetParent)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    return w ? w->parent : 0;
}

H(SetParent)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    uint32_t old = w->parent;
    w->parent = a[1];
    return old;
}

H(IsChild)
{
    UNUSED;
    S();
    Win *w = getwin(a[1]);
    return w && w->parent == a[0];
}

H(GetDlgCtrlID)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    return w ? w->id : 0;
}

static uint32_t *long_field(Win *w, int32_t idx)
{
    switch (idx) {
    case -4: return &w->wndproc;
    case -6: return &w->hinst;
    case -8: return &w->parent;
    case -16: return &w->style;
    case -20: return &w->exstyle;
    case -21: return &w->userdata;
    case -12: return &w->id;
    }
    return NULL;
}

H(GetWindowLongA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    uint32_t *f = long_field(w, (int32_t)a[1]);
    if (f)
        return *f;
    for (uint32_t i = 0; i < w->nextra; i++)
        if (w->extra[i].key == (int32_t)a[1])
            return w->extra[i].val;
    return 0;
}

H(SetWindowLongA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    uint32_t *f = long_field(w, (int32_t)a[1]), old;
    if (f) {
        old = *f;
        *f = a[2];
        return old;
    }
    for (uint32_t i = 0; i < w->nextra; i++)
        if (w->extra[i].key == (int32_t)a[1]) {
            old = w->extra[i].val;
            w->extra[i].val = a[2];
            return old;
        }
    w->extra = realloc(w->extra, (w->nextra + 1) * sizeof *w->extra);
    w->extra[w->nextra++] = (Extra){(int32_t)a[1], a[2]};
    return 0;
}

static Prop *prop_find(Win *w, uint32_t namep)
{
    char name[256];
    class_name(namep, name, sizeof name);
    for (uint32_t i = 0; i < w->nprops; i++)
        if (strcmp(w->props[i].name, name) == 0)
            return &w->props[i];
    return NULL;
}

H(SetPropA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    Prop *p = prop_find(w, a[1]);
    if (!p) {
        w->props = realloc(w->props, (w->nprops + 1) * sizeof *w->props);
        p = &w->props[w->nprops++];
        class_name(a[1], p->name, sizeof p->name);
    }
    p->val = a[2];
    return 1;
}

H(GetPropA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    Prop *p = w ? prop_find(w, a[1]) : NULL;
    return p ? p->val : 0;
}

H(RemovePropA)
{
    UNUSED;
    S();
    Win *w = getwin(a[0]);
    Prop *p = w ? prop_find(w, a[1]) : NULL;
    if (!p)
        return 0;
    uint32_t v = p->val, i = (uint32_t)(p - w->props);
    memmove(&w->props[i], &w->props[i + 1], (w->nprops - i - 1) * sizeof *w->props);
    w->nprops--;
    return v;
}

H(SetWindowTextA)
{
    S();
    if (!getwin(a[0]))
        return 0;
    return send(c, a[0], WM_SETTEXT, 0, a[1]) != 0;
}

H(GetWindowTextA) { S(); return send(c, a[0], WM_GETTEXT, a[2], a[1]); }
H(GetWindowTextLengthA) { S(); return send(c, a[0], WM_GETTEXTLENGTH, 0, 0); }

/* ---------------------------------------------------------------- geometry */
static void rect_of(uint32_t hwnd, int32_t r[4])
{
    Win *w = (hwnd == DESKTOP || hwnd == 0) ? NULL : getwin(hwnd);
    if (!w) {
        r[0] = r[1] = 0, r[2] = (int32_t)SCREEN[0], r[3] = (int32_t)SCREEN[1];
        return;
    }
    r[0] = w->x, r[1] = w->y, r[2] = w->x + w->w, r[3] = w->y + w->h;
}

H(GetWindowRect)
{
    UNUSED;
    S();
    int32_t r[4];
    rect_of(a[0], r);
    memcpy(gptr(a[1]), r, 16);
    return 1;
}

H(GetClientRect)
{
    UNUSED;
    S();
    int32_t r[4], o[4];
    rect_of(a[0], r);
    o[0] = o[1] = 0, o[2] = r[2] - r[0], o[3] = r[3] - r[1];
    memcpy(gptr(a[1]), o, 16);
    return 1;
}

static uint32_t shift_point(uint32_t hwnd, uint32_t pt, int sign)
{
    int32_t r[4], p[2];
    rect_of(hwnd, r);
    memcpy(p, gptr(pt), 8);
    p[0] += sign * r[0], p[1] += sign * r[1];
    memcpy(gptr(pt), p, 8);
    return 1;
}

H(ClientToScreen) { UNUSED; S(); return shift_point(a[0], a[1], 1); }
H(ScreenToClient) { UNUSED; S(); return shift_point(a[0], a[1], -1); }

static void relocate(CPU *c, Win *win, int32_t x, int32_t y, int32_t w, int32_t h)
{
    int moved = x != win->x || y != win->y, sized = w != win->w || h != win->h;
    uint32_t hwnd = win->hwnd;
    win->x = x, win->y = y, win->w = w, win->h = h;
    if (sized)
        send(c, hwnd, WM_SIZE, 0, (((uint32_t)h & 0xFFFF) << 16) | ((uint32_t)w & 0xFFFF));
    if (moved)
        send(c, hwnd, WM_MOVE, 0, (((uint32_t)y & 0xFFFF) << 16) | ((uint32_t)x & 0xFFFF));
}

H(MoveWindow)
{
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    relocate(c, w, (int32_t)a[1], (int32_t)a[2], (int32_t)a[3], (int32_t)a[4]);
    return 1;
}

H(SetWindowPos)
{
    S();
    Win *w = getwin(a[0]);
    if (!w)
        return 0;
    uint32_t flags = a[6], hwnd = a[0];
    int32_t nx = w->x, ny = w->y, nw = w->w, nh = w->h;
    if (!(flags & 2))                   /* SWP_NOMOVE */
        nx = (int32_t)a[2], ny = (int32_t)a[3];
    if (!(flags & 1))                   /* SWP_NOSIZE */
        nw = (int32_t)a[4], nh = (int32_t)a[5];
    relocate(c, w, nx, ny, nw, nh);
    if ((w = getwin(hwnd))) {
        if (flags & 0x40)               /* SWP_SHOWWINDOW */
            w->visible = 1;
        if (flags & 0x80)               /* SWP_HIDEWINDOW */
            w->visible = 0;
    }
    return 1;
}

H(AdjustWindowRectEx)
{
    UNUSED;
    int32_t r[4];
    memcpy(r, gptr(a[0]), 16);
    if ((a[1] & WS_CAPTION) == WS_CAPTION) {
        r[0] -= 3, r[1] -= 22 + (a[2] ? 19 : 0), r[2] += 3, r[3] += 3;
    } else if (a[1] & 0x00800000u) {    /* WS_BORDER */
        r[0] -= 1, r[1] -= 1, r[2] += 1, r[3] += 1;
    }
    memcpy(gptr(a[0]), r, 16);
    return 1;
}

/* ---------------------------------------------------------------- focus and activation */
H(GetFocus) { UNUSED; S(); return W.focus; }

H(SetFocus)
{
    S();
    Win *top = top_level(a[0]);
    if (top && top->hwnd != W.active)
        activate(c, a[0]);
    return set_focus(c, a[0]);
}

H(GetActiveWindow) { UNUSED; S(); return W.active ? W.active : LEGACY_ACTIVE; }
H(SetActiveWindow) { S(); return activate(c, a[0]); }

H(SetForegroundWindow)
{
    S();
    activate(c, a[0]);
    return 1;
}

H(GetCapture) { UNUSED; S(); return W.capture; }

H(SetCapture)
{
    UNUSED;
    S();
    W.capture = a[0];
    return 0;
}

H(ReleaseCapture)
{
    UNUSED;
    S();
    W.capture = 0;
    return 1;
}

H(SetTimer) { UNUSED; return a[1] ? a[1] : 1; }

#define C4 HLE_CORO
const HleDef hle_winsys[] = {
    {U, "RegisterClassA", 1, STDCALL, RegisterClassA},
    {U, "UnregisterClassA", 2, STDCALL, UnregisterClassA},
    {U, "GetClassInfoA", 3, STDCALL, GetClassInfoA},
    {U, "GetClassNameA", 3, STDCALL, GetClassNameA},
    {U, "GetClassLongA", 2, STDCALL, GetClassLongA},
    {U, "SetWindowsHookExA", 4, STDCALL, SetWindowsHookExA},
    {U, "UnhookWindowsHookEx", 1, STDCALL, UnhookWindowsHookEx},
    {U, "CallNextHookEx", 4, STDCALL, Return0},
    {U, "CreateWindowExA", 12, C4, CreateWindowExA},
    {U, "DestroyWindow", 1, C4, DestroyWindow},
    {U, "DefWindowProcA", 4, C4, DefWindowProcA},
    {U, "CallWindowProcA", 5, C4, CallWindowProcA},
    {U, "SendMessageA", 4, C4, SendMessageA},
    {U, "PostMessageA", 4, STDCALL, PostMessageA},
    {U, "PostThreadMessageA", 4, STDCALL, PostThreadMessageA},
    {U, "PostQuitMessage", 1, STDCALL, PostQuitMessage},
    {U, "PeekMessageA", 5, C4, PeekMessageA},
    {U, "GetMessageA", 4, C4, GetMessageA},
    {U, "TranslateMessage", 1, STDCALL, TranslateMessage},
    {U, "DispatchMessageA", 1, C4, DispatchMessageA},
    {U, "IsWindow", 1, STDCALL, IsWindow},
    {U, "IsWindowVisible", 1, STDCALL, IsWindowVisible},
    {U, "IsWindowEnabled", 1, STDCALL, IsWindowEnabled},
    {U, "EnableWindow", 2, STDCALL, EnableWindow},
    {U, "ShowWindow", 2, C4, ShowWindow},
    {U, "GetParent", 1, STDCALL, GetParent},
    {U, "SetParent", 2, STDCALL, SetParent},
    {U, "GetWindow", 2, STDCALL, Return0},
    {U, "IsChild", 2, STDCALL, IsChild},
    {U, "GetDlgCtrlID", 1, STDCALL, GetDlgCtrlID},
    {U, "GetWindowLongA", 2, STDCALL, GetWindowLongA},
    {U, "SetWindowLongA", 3, STDCALL, SetWindowLongA},
    {U, "SetPropA", 3, STDCALL, SetPropA},
    {U, "GetPropA", 2, STDCALL, GetPropA},
    {U, "RemovePropA", 2, STDCALL, RemovePropA},
    {U, "SetWindowTextA", 2, C4, SetWindowTextA},
    {U, "GetWindowTextA", 3, C4, GetWindowTextA},
    {U, "GetWindowTextLengthA", 1, C4, GetWindowTextLengthA},
    {U, "GetWindowRect", 2, STDCALL, GetWindowRect},
    {U, "GetClientRect", 2, STDCALL, GetClientRect},
    {U, "ClientToScreen", 2, STDCALL, ClientToScreen},
    {U, "ScreenToClient", 2, STDCALL, ScreenToClient},
    {U, "MoveWindow", 6, C4, MoveWindow},
    {U, "SetWindowPos", 7, C4, SetWindowPos},
    {U, "AdjustWindowRectEx", 4, STDCALL, AdjustWindowRectEx},
    {U, "GetFocus", 0, STDCALL, GetFocus},
    {U, "SetFocus", 1, C4, SetFocus},
    {U, "GetActiveWindow", 0, STDCALL, GetActiveWindow},
    {U, "SetActiveWindow", 1, C4, SetActiveWindow},
    {U, "GetForegroundWindow", 0, STDCALL, GetActiveWindow},
    {U, "SetForegroundWindow", 1, C4, SetForegroundWindow},
    {U, "BringWindowToTop", 1, STDCALL, Return1},
    {U, "GetCapture", 0, STDCALL, GetCapture},
    {U, "SetCapture", 1, STDCALL, SetCapture},
    {U, "ReleaseCapture", 0, STDCALL, ReleaseCapture},
    {U, "UpdateWindow", 1, STDCALL, Return1},
    {U, "InvalidateRect", 3, STDCALL, Return1},
    {U, "SetTimer", 4, STDCALL, SetTimer},
    {U, "KillTimer", 2, STDCALL, Return1},
    {U, "MapWindowPoints", 4, STDCALL, Return0},
    {NULL, NULL, 0, 0, NULL},
};
