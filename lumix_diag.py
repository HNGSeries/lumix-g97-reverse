#!/usr/bin/env python3
"""
lumix_diag.py - find the working transport/frame format for the G97 04da:2370
service dispatcher. We can open it and send, but the GX9-derived 0x5c read got no
reply, so this tries several READ handshakes x several simple read ops and prints
whatever comes back. Read-only, safe ops/addresses only (no 0x70, no 0x40000000).

Run while the camera is in DISP+AF/AE LOCK service mode with WinUSB bound.
"""
import sys, struct, time
try:
    import libusb_package, usb.core, usb.util
except Exception as e:
    raise SystemExit("need pyusb+libusb-package: pip install pyusb libusb-package (%s)" % e)

def backend():
    try:
        import libusb_package
        return libusb_package.get_libusb1_backend()
    except Exception:
        return None

dev = usb.core.find(idVendor=0x04da, idProduct=0x2370, backend=backend())
if dev is None:
    raise SystemExit("04da:2370 not found - camera in DISP+AFL service mode + WinUSB bound?")
try:
    dev.set_configuration()
except Exception:
    pass
cfg = dev.get_active_configuration()
ep_out = ep_in = None
for intf in cfg:
    for ep in intf:
        d = usb.util.endpoint_direction(ep.bEndpointAddress)
        t = usb.util.endpoint_type(ep.bmAttributes)
        if t == usb.util.ENDPOINT_TYPE_BULK and d == usb.util.ENDPOINT_OUT and ep_out is None:
            ep_out = ep
        if t == usb.util.ENDPOINT_TYPE_BULK and d == usb.util.ENDPOINT_IN and ep_in is None:
            ep_in = ep
print("dev 04da:2370  OUT 0x%02x  IN 0x%02x" % (ep_out.bEndpointAddress, ep_in.bEndpointAddress))

def setup(idx):
    try:
        dev.ctrl_transfer(0x40, 0, 0, idx, None, timeout=1500)
    except Exception as e:
        print("     (ctrl setup idx%d err: %s)" % (idx, e))

def frame8(op, operands=b''):
    f = bytearray(16)
    f[0] = 0x08; f[1] = 0x00; f[2] = 0xff; f[3] = op
    f[4:4+len(operands)] = operands
    f[14] = sum(f[1:14]) & 0xff
    f[15] = 0x00
    return bytes(f)

def try_read(label):
    # read 1 byte first then the rest (doc style), fall back to bulk read
    try:
        got = ep_in.read(2048, timeout=1500).tobytes()
        print("     %-28s REPLY %dB: %s" % (label, len(got), got[:48].hex()))
        return got
    except usb.core.USBError as e:
        print("     %-28s %s" % (label, type(e).__name__))
        return None

def var_A(fr):  # doc: setup0/OUT, setup1/IN
    setup(0); ep_out.write(fr, 1500); setup(1); return try_read("A setup0-out setup1-in")
def var_B(fr):  # no setups
    ep_out.write(fr, 1500); return try_read("B out in")
def var_C(fr):  # setup0/OUT, IN (no setup before in)
    setup(0); ep_out.write(fr, 1500); return try_read("C setup0-out in")
def var_D(fr):  # setup1 before both
    setup(1); ep_out.write(fr, 1500); setup(1); return try_read("D setup1-out setup1-in")
def var_E(fr):  # setup0 before OUT only, then read twice (device may send 1B then frame)
    setup(0); ep_out.write(fr, 1500); setup(1)
    try:
        a = ep_in.read(1, timeout=1500).tobytes()
        b = ep_in.read(2048, timeout=1500).tobytes()
        print("     E 1byte+rest             REPLY %dB: %s" % (len(a)+len(b), (a+b)[:48].hex()))
    except usb.core.USBError as e:
        print("     E 1byte+rest             %s" % type(e).__name__)

VARIANTS = [var_A, var_B, var_C, var_D, var_E]

OPS = {
    '0x9b @0x80208000 (abs 2B read)': frame8(0x9b, struct.pack('<I', 0x80208000)),
    '0x35 idx0 sel0x10 (word read)':  frame8(0x35, struct.pack('<H', 0) + bytes([0x10])),
    '0x38 area0x20 idx0':             frame8(0x38, bytes([0x20]) + struct.pack('<H', 0)),
}

for opname, fr in OPS.items():
    print("\n== %s   frame=%s ==" % (opname, fr.hex()))
    for vfn in VARIANTS:
        try:
            vfn(fr)
        except usb.core.USBError as e:
            print("     (write err: %s)" % type(e).__name__)
        time.sleep(0.2)

print("\ndone. If any line shows REPLY, note the variant+op - that's the working transport.")
