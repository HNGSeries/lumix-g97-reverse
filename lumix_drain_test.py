#!/usr/bin/env python3
"""
lumix_drain_test.py - hypothesis: the dispatcher crashes after ~40-75 commands
because it queues events on the interrupt IN endpoint (0x83) that we never read,
and the queue wedges it. Fix: drain 0x83 after every command.

Reads 0x9b in a loop AND drains the interrupt endpoint each iteration; reports how
many succeed. If this blows past ~75 (e.g. hundreds/thousands), interrupt-drain is
THE fix and a full dump becomes possible. Run on a FRESH service-mode entry.
"""
import sys, time
import usb.util
from lumix_native import Native, PROGRAM_RAM_START

d = Native()
int_ep = None
for intf in d.dev.get_active_configuration():
    for ep in intf:
        if (usb.util.endpoint_direction(ep.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(ep.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR):
            int_ep = ep
print("interrupt IN endpoint:", ('0x%02x' % int_ep.bEndpointAddress) if int_ep else "NONE")

def drain():
    if int_ep is None:
        return
    for _ in range(4):
        try:
            got = int_ep.read(64, 30).tobytes()
            if not got:
                break
        except Exception:
            break

base = PROGRAM_RAM_START
ok = 0
drain()  # clear anything pending at start
while ok < 3000:
    try:
        v = d.read16(base + ok * 2)
        if not v:
            raise RuntimeError("empty")
        ok += 1
        drain()
        if ok % 50 == 0:
            sys.stderr.write("\r  %d reads ok" % ok); sys.stderr.flush()
    except Exception as e:
        sys.stderr.write("\n")
        print("FAILED after %d reads (%d bytes): %s" % (ok, ok * 2, type(e).__name__))
        break
else:
    print("\n%d reads with NO failure -> interrupt-drain FIXES it! full dump now viable." % ok)

print("(baseline without drain was ~61 reads; compare.)")
