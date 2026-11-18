#!/usr/bin/env python3
"""
lumix_usb_probe.py - raw PTP-over-USB prober for LUMIX service/native protocol RE.

Goal of Track A: find the camera's memory-read primitive (the native/service
dispatcher the GM1/GX9 work used) so we can pull the ALREADY-DECRYPTED firmware
out of the running camera over USB, instead of attacking the AES.

This talks raw PTP bulk transport via pyusb, so we can send ANY opcode including
the Panasonic vendor opcodes (0x9102/0x9103/0x9104 seen on S5M2). It:
  --list            open session, dump DeviceInfo, list SupportedOperations
                    (flags vendor opcodes >= 0x9000)
  --raw OP [P...]   send one transaction (receiving data phase) and hexdump reply
  --send OP [P...] --data HEX   send with a data phase (OUT)

SETUP (Windows 11):
  1. Set the camera USB mode to "PC(Tether)"/"PC" and connect.
  2. The camera enumerates as an MTP/WPD device. To use libusb, rebind its
     interface to WinUSB with Zadig (https://zadig.akeo.ie): select the LUMIX
     device, choose WinUSB, Replace Driver. (Undo later via Device Manager.)
  3. pip install pyusb ; libusb-1.0 DLL on PATH (comes with the libusb release).
  Alt (no driver swap): the Windows Portable Devices (WPD) API can send vendor
  opcodes via WPD_CATEGORY_MTP_EXT_VENDOR_OPERATIONS -- see README (ShaoCI route).

SAFETY: --list and GetDeviceInfo are read-only and safe. Vendor opcodes are
UNKNOWN territory; some may write/erase. Probe read-shaped opcodes first, one at
a time, with the SD card removed and battery full. You accept the risk.
"""
import sys, struct, argparse, time

PANASONIC_VID = 0x04da

# PTP container types
CMD, DATA, RESP, EVENT = 1, 2, 3, 4
# Standard ops
OP_GETDEVICEINFO = 0x1001
OP_OPENSESSION   = 0x1002
OP_CLOSESESSION  = 0x1003
RESP_OK          = 0x2001

def _need_pyusb():
    try:
        import usb.core, usb.util  # noqa
        return __import__('usb.core', fromlist=['core']), __import__('usb.util', fromlist=['util'])
    except Exception as e:
        raise SystemExit("pyusb not available: %s\n  pip install pyusb  (and install libusb-1.0)" % e)

def _backend():
    """Use the bundled libusb from libusb-package so no manual DLL is needed."""
    try:
        import libusb_package
        return libusb_package.get_libusb1_backend()
    except Exception:
        return None

class PTP:
    def __init__(self, vid=PANASONIC_VID, pid=None):
        import usb.core, usb.util
        self.usb = usb.util
        be = _backend()
        kw = {'idVendor': vid, 'backend': be}
        if pid:
            kw['idProduct'] = pid
        dev = usb.core.find(**kw)
        if dev is None:
            # fall back: any still-image class (0x06) interface
            dev = usb.core.find(find_all=False, backend=be,
                    custom_match=lambda d: any(
                        i.bInterfaceClass == 6
                        for c in d for i in c))
        if dev is None:
            raise SystemExit("no camera found (VID 0x%04x). Connected? WinUSB bound?" % vid)
        self.dev = dev
        # Inspect descriptors WITHOUT opening (works even while bound to usbstor/WpdMtp)
        classes = set()
        for cfg in dev:
            for i in cfg:
                classes.add(i.bInterfaceClass)
        if 6 not in classes and 0xff not in classes and 8 in classes:
            raise SystemExit(
                "found %04x:%04x in USB Mass-Storage mode.\n"
                "  On the camera: Menu > Setup (wrench) > USB Mode > PC(Tether)\n"
                "  [or PC / PictBridge(PTP)], then reconnect and re-run."
                % (dev.idVendor, dev.idProduct))
        try:
            dev.set_configuration()
            cfg = dev.get_active_configuration()
        except (NotImplementedError, usb.core.USBError) as e:
            raise SystemExit(
                "found %04x:%04x but libusb can't open it: %s\n"
                "  On Windows, bind WinUSB to the LUMIX interface with Zadig\n"
                "  (https://zadig.akeo.ie): select the device, pick WinUSB, Replace Driver.\n"
                "  Revert later via Device Manager > uninstall device." % (dev.idVendor, dev.idProduct, e))
        intf = None
        for i in cfg:
            if i.bInterfaceClass == 6 and intf is None:  # still image / PTP
                intf = i
        if intf is None:
            intf = cfg[(0, 0)]
        self.ep_out = usb.util.find_descriptor(intf, custom_match=lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT and
            usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK)
        self.ep_in = usb.util.find_descriptor(intf, custom_match=lambda e:
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN and
            usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK)
        self.tid = 0
        print("device: %04x:%04x  %s" % (dev.idVendor, dev.idProduct,
              (dev.product or '?')))

    def _send_container(self, ctype, code, params=(), payload=b''):
        self.tid += 1
        body = b''.join(struct.pack('<I', p & 0xffffffff) for p in params) + payload
        hdr = struct.pack('<IHHI', 12 + len(body), ctype, code, self.tid)
        self.ep_out.write(hdr + body, timeout=5000)

    def _read_container(self, timeout=5000):
        data = self.ep_in.read(512, timeout=timeout).tobytes()
        if len(data) < 12:
            return None
        length, ctype, code, tid = struct.unpack_from('<IHHI', data, 0)
        buf = bytearray(data)
        while len(buf) < length:
            chunk = self.ep_in.read(min(16384, length - len(buf)), timeout=timeout).tobytes()
            if not chunk:
                break
            buf += chunk
        return ctype, code, tid, bytes(buf[12:length])

    def transaction(self, code, params=(), out_data=None):
        """One PTP transaction. Returns (resp_code, data_bytes)."""
        if out_data is None:
            self._send_container(CMD, code, params)
        else:
            self._send_container(CMD, code, params)
            self._send_container(DATA, code, params, out_data)
        data = b''
        resp = None
        for _ in range(64):
            c = self._read_container()
            if c is None:
                break
            ctype, rcode, tid, payload = c
            if ctype == DATA:
                data += payload
            elif ctype == RESP:
                resp = rcode
                break
        return resp, data

    def open_session(self):
        return self.transaction(OP_OPENSESSION, (1,))[0]

    def close_session(self):
        return self.transaction(OP_CLOSESESSION)[0]

def parse_deviceinfo(d):
    """Minimal DeviceInfo parser -> dict with the arrays we care about."""
    import struct as s
    o = 0
    def u16():
        nonlocal o; v = s.unpack_from('<H', d, o)[0]; o += 2; return v
    def u32():
        nonlocal o; v = s.unpack_from('<I', d, o)[0]; o += 4; return v
    def arr16():
        n = u32(); return [u16() for _ in range(n)]
    def pstr():
        nonlocal o
        n = d[o]; o += 1
        txt = d[o:o+n*2].decode('utf-16-le', 'replace').rstrip('\x00'); o += n*2
        return txt
    info = {}
    info['StandardVersion'] = u16()
    info['VendorExtensionID'] = u32()
    info['VendorExtensionVersion'] = u16()
    info['VendorExtensionDesc'] = pstr()
    info['FunctionalMode'] = u16()
    info['OperationsSupported'] = arr16()
    info['EventsSupported'] = arr16()
    info['DevicePropertiesSupported'] = arr16()
    info['CaptureFormats'] = arr16()
    info['ImageFormats'] = arr16()
    info['Manufacturer'] = pstr()
    info['Model'] = pstr()
    info['DeviceVersion'] = pstr()
    info['SerialNumber'] = pstr()
    return info

def hexdump(b, limit=512):
    b = b[:limit]
    for i in range(0, len(b), 16):
        row = b[i:i+16]
        hexs = ' '.join('%02x' % x for x in row)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
        print("  %08x  %-47s  %s" % (i, hexs, asc))
    if len(b) == limit:
        print("  ... (truncated)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vid', type=lambda x: int(x, 0), default=PANASONIC_VID)
    ap.add_argument('--pid', type=lambda x: int(x, 0), default=None)
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--raw', type=lambda x: int(x, 0), help='opcode to send (hex ok)')
    ap.add_argument('params', nargs='*', help='u32 params for --raw/--send')
    ap.add_argument('--data', help='hex payload for an OUT data phase')
    ap.add_argument('--allow-vendor', action='store_true',
                    help='required to send opcodes >= 0x9000')
    a = ap.parse_args()
    _need_pyusb()

    p = PTP(a.vid, a.pid)
    r = p.open_session()
    print("OpenSession -> 0x%04x" % (r or 0))

    if a.list or a.raw is None:
        resp, data = p.transaction(OP_GETDEVICEINFO)
        print("GetDeviceInfo -> 0x%04x, %d bytes" % (resp or 0, len(data)))
        try:
            info = parse_deviceinfo(data)
            print("  Manufacturer:", info['Manufacturer'])
            print("  Model:       ", info['Model'])
            print("  DeviceVersion:", info['DeviceVersion'])
            print("  VendorExtDesc:", info['VendorExtensionDesc'])
            ops = info['OperationsSupported']
            print("  OperationsSupported (%d):" % len(ops))
            for op in ops:
                tag = '  <-- VENDOR' if op >= 0x9000 else ''
                print("     0x%04x%s" % (op, tag))
            props = info['DevicePropertiesSupported']
            print("  DevicePropertiesSupported (%d): %s" %
                  (len(props), ' '.join('0x%04x' % x for x in props)))
        except Exception as e:
            print("  (DeviceInfo parse failed: %s)" % e)
            hexdump(data)

    if a.raw is not None:
        op = a.raw
        if op >= 0x9000 and not a.allow_vendor:
            raise SystemExit("opcode 0x%04x is vendor; re-run with --allow-vendor "
                             "(understand it may write/erase)." % op)
        params = [int(x, 0) for x in a.params]
        out = bytes.fromhex(a.data) if a.data else None
        print("TX op=0x%04x params=%s data=%s" %
              (op, params, (a.data[:32]+'...') if a.data else None))
        resp, data = p.transaction(op, params, out)
        print("RESP 0x%04x, %d data bytes:" % (resp or 0, len(data)))
        hexdump(data)

    p.close_session()

if __name__ == '__main__':
    main()
