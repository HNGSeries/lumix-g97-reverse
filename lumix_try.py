#!/usr/bin/env python3
"""
lumix_try.py - ONE clean command to the 04da:2370 service dispatcher, reading the
FULL reply frame. The dispatcher is state-sensitive: the first command after a
clean power-up replies; a desync silences it. So:

  *** FULLY power-cycle the camera (switch OFF; if unsure, pop the battery ~5s),
      then re-enter service mode (take a photo, power ON holding DISP+AF/AE LOCK),
      and run this ONCE. ***

Read-only, safe default op (0x9b absolute 2-byte read at a GX9-verified address).

Examples:
  py -3 lumix_try.py                      # 0x9b @0x80208000, handshake A
  py -3 lumix_try.py --op 0x9b --addr 0x83e80000
  py -3 lumix_try.py --op 0x35
  py -3 lumix_try.py --no-setup
  py -3 lumix_try.py --setup-in 0
"""
import sys, struct, argparse, time
import usb.core, usb.util

CLASS_LEN = {0x08: 16, 0x01: 1030, 0x02: 32774, 0x03: 8198, 0x04: 4102, 0x05: 106, 0x10: 262}

def backend():
    try:
        import libusb_package
        return libusb_package.get_libusb1_backend()
    except Exception:
        return None

ap = argparse.ArgumentParser()
ap.add_argument('--op', type=lambda x: int(x, 0), default=0x9b)
ap.add_argument('--addr', type=lambda x: int(x, 0), default=0x80208000)
ap.add_argument('--operands', help='explicit operand hex (overrides --addr)')
ap.add_argument('--no-setup', action='store_true')
ap.add_argument('--setup-out', type=int, default=0)
ap.add_argument('--setup-in', type=int, default=1)
ap.add_argument('--timeout', type=int, default=2000)
a = ap.parse_args()

dev = usb.core.find(idVendor=0x04da, idProduct=0x2370, backend=backend())
if dev is None:
    raise SystemExit("04da:2370 not found - need a FRESH DISP+AF/AE LOCK service mode + WinUSB bound.")
try:
    dev.set_configuration()
except Exception:
    pass
cfg = dev.get_active_configuration()
ep_out = ep_bulk_in = ep_int_in = None
for intf in cfg:
    for ep in intf:
        d = usb.util.endpoint_direction(ep.bEndpointAddress)
        t = usb.util.endpoint_type(ep.bmAttributes)
        if d == usb.util.ENDPOINT_OUT and t == usb.util.ENDPOINT_TYPE_BULK and ep_out is None:
            ep_out = ep
        if d == usb.util.ENDPOINT_IN and t == usb.util.ENDPOINT_TYPE_BULK and ep_bulk_in is None:
            ep_bulk_in = ep
        if d == usb.util.ENDPOINT_IN and t == usb.util.ENDPOINT_TYPE_INTR and ep_int_in is None:
            ep_int_in = ep
print("OUT 0x%02x  BULK-IN 0x%02x  INT-IN %s" % (
    ep_out.bEndpointAddress, ep_bulk_in.bEndpointAddress,
    ('0x%02x' % ep_int_in.bEndpointAddress) if ep_int_in else 'none'))

def setup(idx):
    try:
        dev.ctrl_transfer(0x40, 0, 0, idx, None, timeout=1500)
    except Exception as e:
        print("  ctrl setup %d: %s" % (idx, type(e).__name__))

if a.operands is not None:
    operands = bytes.fromhex(a.operands)
elif a.op == 0x9b:
    operands = struct.pack('<I', a.addr)
elif a.op == 0x35:
    operands = struct.pack('<H', a.addr & 0xffff) + bytes([0x10])
else:
    operands = b''
f = bytearray(16)
f[0] = 0x08; f[1] = 0x00; f[2] = 0xff; f[3] = a.op
f[4:4+len(operands)] = operands
f[14] = sum(f[1:14]) & 0xff
frame = bytes(f)
print("TX frame:", frame.hex())

if not a.no_setup:
    setup(a.setup_out)
try:
    n = ep_out.write(frame, a.timeout)
    print("OUT wrote %d bytes OK" % n)
except usb.core.USBError as e:
    raise SystemExit("OUT write FAILED (%s) -> dispatcher hung; FULL power-cycle + re-enter." % type(e).__name__)
def rd(nbytes, tmo):
    """One IN phase = vendor ctrl setup(1) THEN a bulk read (doc: setup before each IN)."""
    if not a.no_setup:
        setup(a.setup_in)
    try:
        return ep_bulk_in.read(nbytes, tmo).tobytes()
    except usb.core.USBError:
        return b''

# Phase 1: the one-byte type (retry for latency)
t = b''
deadline = time.time() + 6.0
while not t and time.time() < deadline:
    t = rd(1, 700)

if not t:
    print("BULK-IN: no reply (no type byte)")
    if ep_int_in is not None:
        try:
            gi = ep_int_in.read(64, 1500).tobytes()
            print("INT-IN : %s" % gi.hex())
        except usb.core.USBError:
            print("INT-IN : no reply")
else:
    cls = t[0]
    L = CLASS_LEN.get(cls, 16)
    print("type byte 0x%02x -> expecting %d-byte frame" % (cls, L))
    # Phase 2: the full frame, each read preceded by its own setup(1)
    buf = bytearray()
    deadline = time.time() + 6.0
    while len(buf) < L and time.time() < deadline:
        c = rd(L - len(buf), 1500)
        if not c:
            break
        buf += c
    print("BULK-IN frame %dB: %s" % (len(buf), buf.hex()))
    if cls == 0x08 and len(buf) >= 6:
        print("   -> reply op 0x%02x, data[4:6]=%s (LE 0x%04x)" %
              (buf[3], buf[4:6].hex(), int.from_bytes(buf[4:6], 'little')))
print("done.")
