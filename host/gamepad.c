/* Game controllers for the live view (host/live.c): an Xbox, PlayStation or other pad SDL3 knows (on macOS through
 * GameController.framework and IOKit HID), played as the keyboard and mouse the game's default bindings expect
 * (Input Settings in the registry): the game itself never sees a joystick (hle_dinput.c provides none). Once per
 * frame the first connected pad's state is read and its changes become DIK key presses, mouse buttons and wheel
 * notches; the right stick becomes mouse motion, in pixels per second with a response curve, which live.c adds to
 * the real mouse's. Two layouts (--pad), labels Xbox's (A south, B east, X west, Y north); both move with the left
 * stick (W A S D) and aim with the right stick (the mouse):
 *              modern (the default)                     classic (the PC controls as they are)
 *   RT         fire (left button)                       fire (left button)
 *   LT         Bullet Time Toggle (V)                   bullet time / shootdodge (right button)
 *   RB         shootdodge, bullet time standing (right) next weapon (wheel up)
 *   LB         weapon category 6 (6)                    previous weapon (wheel down)
 *   A B X Y    jump (Space), crouch (C), reload (R), use and menu select (Enter)       (the same)
 *   D-pad      left/right previous/next weapon ([ ]),   arrow keys (menus; in a level they move too)
 *              up painkiller (Backspace), down reload (R)
 *   L3 / R3    Q / -                                    Q / painkiller (Backspace)
 *   Start/Back menu (Esc) / Tab                         (the same)
 * Bullet Time Toggle has no key by default: V is a spare one, bound once in Options > Controls by pressing LT there.
 * --pad-look N (the right stick's top speed, default 1008 px/s) and --pad-invert (vertical look) tune the aim. */
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <SDL3/SDL.h>

#include "host.h"

#define STICK_ON 0.45f                          /* a stick past this presses its key, back under STICK_OFF releases */
#define STICK_OFF 0.30f
#define TRIGGER_ON 0.40f
#define TRIGGER_OFF 0.25f
#define LOOK_DEADZONE 0.12f
#define LOOK_CURVE 2.0                          /* deflection^curve: fine aim near the centre */

/* what a button or trigger sends: a key (DIK), a mouse button (0 left, 1 right) or a wheel notch (+1 up, -1 down,
 * on press) */
enum { OUT_NONE, OUT_KEY, OUT_MOUSE, OUT_WHEEL };
typedef struct { uint8_t kind; int8_t code; uint8_t dik; } Out;
#define KEY(d) {OUT_KEY, 0, d}
#define MOUSE(n) {OUT_MOUSE, n, 0}
#define WHEEL(n) {OUT_WHEEL, n, 0}
#define TRIG_RT SDL_GAMEPAD_BUTTON_COUNT        /* the triggers follow the buttons */
#define TRIG_LT (SDL_GAMEPAD_BUTTON_COUNT + 1)
#define NOUT (SDL_GAMEPAD_BUTTON_COUNT + 2)
#define FACE_AND_MENU                                                                                                  \
    [SDL_GAMEPAD_BUTTON_SOUTH] = KEY(0x39), [SDL_GAMEPAD_BUTTON_EAST] = KEY(0x2e),                                     \
    [SDL_GAMEPAD_BUTTON_WEST] = KEY(0x13), [SDL_GAMEPAD_BUTTON_NORTH] = KEY(0x1c),                                     \
    [SDL_GAMEPAD_BUTTON_START] = KEY(0x01), [SDL_GAMEPAD_BUTTON_BACK] = KEY(0x0f),                                     \
    [SDL_GAMEPAD_BUTTON_LEFT_STICK] = KEY(0x10), [TRIG_RT] = MOUSE(0)
static const Out MODERN[NOUT] = {
    FACE_AND_MENU, [TRIG_LT] = KEY(0x2f), [SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER] = MOUSE(1),
    [SDL_GAMEPAD_BUTTON_LEFT_SHOULDER] = KEY(0x07), [SDL_GAMEPAD_BUTTON_DPAD_LEFT] = KEY(0x1a),
    [SDL_GAMEPAD_BUTTON_DPAD_RIGHT] = KEY(0x1b), [SDL_GAMEPAD_BUTTON_DPAD_UP] = KEY(0x0e),
    [SDL_GAMEPAD_BUTTON_DPAD_DOWN] = KEY(0x13)};
static const Out CLASSIC[NOUT] = {
    FACE_AND_MENU, [TRIG_LT] = MOUSE(1), [SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER] = WHEEL(1),
    [SDL_GAMEPAD_BUTTON_LEFT_SHOULDER] = WHEEL(-1), [SDL_GAMEPAD_BUTTON_RIGHT_STICK] = KEY(0x0e),
    [SDL_GAMEPAD_BUTTON_DPAD_UP] = KEY(0xc8), [SDL_GAMEPAD_BUTTON_DPAD_DOWN] = KEY(0xd0),
    [SDL_GAMEPAD_BUTTON_DPAD_LEFT] = KEY(0xcb), [SDL_GAMEPAD_BUTTON_DPAD_RIGHT] = KEY(0xcd)};
/* the left stick's four directions: W S A D */
static const uint8_t MOVE_DIK[4] = {0x11, 0x1f, 0x1e, 0x20};

static struct {
    SDL_Gamepad *pad;
    SDL_JoystickID id;
    const Out *layout;
    uint8_t held[NOUT], move[4];              /* buttons, then the triggers */
    double look, last;
    int invert;
} P = {.layout = MODERN, .look = 1008.0};

/* mphost's --pad, --pad-look, --pad-invert */
void gamepad_config(int modern, double look, int invert)
{
    P.layout = modern ? MODERN : CLASSIC;
    if (look > 0)
        P.look = look;
    P.invert = invert;
}

static void emit(const Out *o, int down)
{
    if (o->kind == OUT_KEY)
        host_key(o->dik, down);
    else if (o->kind == OUT_MOUSE)
        host_mouse_button((uint32_t)o->code, down);
    else if (o->kind == OUT_WHEEL && down)
        host_mouse_wheel(o->code * 120);
}

/* every key and button the pad holds, released */
static void release_all(void)
{
    for (int i = 0; i < NOUT; i++)
        if (P.held[i])
            emit(&P.layout[i], 0);
    for (int i = 0; i < 4; i++)
        if (P.move[i])
            host_key(MOVE_DIK[i], 0);
    memset(P.held, 0, sizeof P.held);
    memset(P.move, 0, sizeof P.move);
}

static void open_pad(SDL_JoystickID id)
{
    if (P.pad || !(P.pad = SDL_OpenGamepad(id)))
        return;
    P.id = id;
    P.last = 0;
    printf("gamepad: %s connected, %s layout\n", SDL_GetGamepadName(P.pad), P.layout == MODERN ? "modern" : "classic");
    if (P.layout == MODERN)
        printf("gamepad: bind Bullet Time Toggle to LT once: Options > Controls, select it, press LT\n");
}

/* connection events from live.c's pump */
void gamepad_event(const SDL_Event *ev)
{
    if (ev->type == SDL_EVENT_GAMEPAD_ADDED) {
        open_pad(ev->gdevice.which);
    } else if (ev->type == SDL_EVENT_GAMEPAD_REMOVED && P.pad && ev->gdevice.which == P.id) {
        printf("gamepad: %s disconnected\n", SDL_GetGamepadName(P.pad));
        release_all();
        SDL_CloseGamepad(P.pad);
        P.pad = NULL;
        int n;
        SDL_JoystickID *ids = SDL_GetGamepads(&n);
        if (ids && n)
            open_pad(ids[0]);
        SDL_free(ids);
    }
}

/* the window lost focus: the game released its keys (host_focus_lost), so forget ours */
void gamepad_focus_lost(void)
{
    memset(P.held, 0, sizeof P.held);
    memset(P.move, 0, sizeof P.move);
    P.last = 0;
}

static float axis(SDL_GamepadAxis a) { return SDL_GetGamepadAxis(P.pad, a) / 32767.0f; }

/* a held flag with hysteresis; returns 1 when it changed */
static int latch(uint8_t *held, float v, float on, float off)
{
    int h = *held ? v > off : v > on;
    if (h == *held)
        return 0;
    *held = (uint8_t)h;
    return 1;
}

/* a frame starts: the pad's changes to the game, the right stick's motion added to *dx, *dy (now: seconds) */
void gamepad_frame(double now, double *dx, double *dy)
{
    if (!P.pad)
        return;
    for (int b = 0; b < SDL_GAMEPAD_BUTTON_COUNT; b++) {
        uint8_t d = SDL_GetGamepadButton(P.pad, (SDL_GamepadButton)b);
        if (d != P.held[b])
            emit(&P.layout[b], P.held[b] = d);
    }
    float lx = axis(SDL_GAMEPAD_AXIS_LEFTX), ly = axis(SDL_GAMEPAD_AXIS_LEFTY);
    const float dir[4] = {-ly, ly, -lx, lx};
    for (int i = 0; i < 4; i++)
        if (latch(&P.move[i], dir[i], STICK_ON, STICK_OFF))
            host_key(MOVE_DIK[i], P.move[i]);
    const float trig[2] = {axis(SDL_GAMEPAD_AXIS_RIGHT_TRIGGER), axis(SDL_GAMEPAD_AXIS_LEFT_TRIGGER)};
    for (int i = 0; i < 2; i++)
        if (latch(&P.held[TRIG_RT + i], trig[i], TRIGGER_ON, TRIGGER_OFF))
            emit(&P.layout[TRIG_RT + i], P.held[TRIG_RT + i]);

    double dt = P.last ? now - P.last : 0;
    P.last = now;
    if (dt > 0.1)
        dt = 0.1;                               /* a long frame (a level loading) is not a long turn */
    float rx = axis(SDL_GAMEPAD_AXIS_RIGHTX), ry = axis(SDL_GAMEPAD_AXIS_RIGHTY);
    double m = sqrt(rx * rx + ry * ry);
    if (m > LOOK_DEADZONE && dt > 0) {
        double mag = ((m > 1 ? 1 : m) - LOOK_DEADZONE) / (1 - LOOK_DEADZONE);
        double speed = P.look * pow(mag, LOOK_CURVE) * dt / m;
        *dx += rx * speed;
        *dy += (P.invert ? -ry : ry) * speed;
    }
}
