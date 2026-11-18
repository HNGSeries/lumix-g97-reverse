#!/usr/bin/env python3
"""
lumix_wordstress.py - does the WORD-read path (0x9b) survive longer than the
1 KiB block path (0x5c)? 0x5c crashes the dispatcher after ~9-75 reads; if 0x9b
is a more stable code path we could dump reliably (slowly) with no power-cycles.

Reads 2 bytes at a time via 0x9b in a tight loop and reports how many succeed
before any failure. Run on a FRESH service-mode entry (power-cycle + DISP+AF/AE LOCK).
"""
import sys, time
from lumix_native import Native, PROGRAM_RAM_START

d = Native()
base = PROGRAM_RAM_START
ok = 0
t0 = time.time()
LIMIT = 4000
while ok < LIMIT:
    try:
        v = d.read16(base + ok * 2)
        if not v:
            raise RuntimeError("empty reply")
        ok += 1
        if ok % 100 == 0:
            rate = ok / max(0.001, time.time() - t0)
            sys.stderr.write("\r  %d words ok (%.0f/s)" % (ok, rate)); sys.stderr.flush()
    except Exception as e:
        sys.stderr.write("\n")
        print("0x9b FAILED after %d good reads (%d bytes) at 0x%08x: %s" %
              (ok, ok * 2, base + ok * 2, type(e).__name__))
        break
else:
    print("\n0x9b did %d reads with NO failure -> word-read path looks STABLE." % ok)

if ok >= 500:
    print("=> 0x9b survived %d reads. If it keeps going, a slow full dump is viable." % ok)
elif ok > 0:
    print("=> only %d reads before failure -- same instability as 0x5c." % ok)
