#!/usr/bin/env python3
"""
lumix_pingtest.py - is the dispatcher DEAD or just DESYNCED after a 0x5c stall?

Reads 1 KiB blocks until one stalls (no reply), then -- in the SAME process, with
NO USB reset -- immediately tries 0x9b word reads. If 0x9b still answers, the
dispatcher is alive and the block stream just lost sync (recoverable); if 0x9b also
times out, the dispatcher is truly dead (needs a power-cycle).

Run on a FRESH service-mode entry (power-cycle + DISP+AF/AE LOCK first).
"""
import sys, time
from lumix_native import Native, PROGRAM_RAM_START

d = Native()
base = PROGRAM_RAM_START
n = 0
stalled = False
while n < 300:
    try:
        d.read_block(base + n * 1024)
        n += 1
        if n % 10 == 0:
            sys.stderr.write("\r  %d blocks ok" % n); sys.stderr.flush()
    except Exception as e:
        sys.stderr.write("\n")
        print("0x5c STALLED after %d good blocks (next addr 0x%08x): %s" %
              (n, base + n * 1024, e))
        stalled = True
        break

if not stalled:
    print("\nno stall in %d blocks - dispatcher is unexpectedly healthy this run!" % n)
    sys.exit(0)

print("--- immediately probing 0x9b (no reset) to see if dispatcher is alive ---")
alive = False
for i in range(4):
    try:
        v = d.read16(0x80208000)
        print("  0x9b @0x80208000 -> %s   *** DISPATCHER ALIVE (block stream just desynced) ***" % v.hex())
        alive = True
        break
    except Exception as e:
        print("  0x9b attempt %d: %s" % (i + 1, type(e).__name__))
        time.sleep(0.3)

if not alive:
    print("  0x9b also dead -> dispatcher truly hung, power-cycle required.")
else:
    print("  => we can likely RESYNC and keep dumping. Tell Claude: ALIVE.")
