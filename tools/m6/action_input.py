"""Print the --input string of the scripted action workload (H53): Enter on the main menu's default item (Resume
Game: the newest save in the data dir), then from frame 200 sweep the view left and right, walk forward (W) and back
(S), and fire a burst every 12 frames. Usage: run_init.py ... --input "$(python3 tools/m6/action_input.py [FRAMES])"
"""
import sys
n = int(sys.argv[1]) if len(sys.argv) > 1 else 1300
a = ["25:key=1c", "26:keyup=1c", "220:key=11", "420:keyup=11", "430:key=1f", "520:keyup=1f"]
a += ["%d:move=%d;0" % (f, 6 if (f // 150) % 2 == 0 else -6) for f in range(200, n)]
for f in range(250, n, 12):
    a += ["%d:button=0" % f, "%d:buttonup=0" % (f + 3)]
print(",".join(a))
