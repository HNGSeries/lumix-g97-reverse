#!/usr/bin/env python3
"""
lumix_native.py - client for the LUMIX *native/service* USB dispatcher.

This is the channel the flickering-star GX9 work used to read the camera's
DECRYPTED RAM (and thus recover the firmware + the AES key). It is NOT the
normal PTP/MTP tether channel -- it is a lower-level dispatcher reachable only
once the camera is in a service/native mode (entry = model-specific, see README:
this is the open gap for the G97).

Protocol (reverse-engineered on GX9 / DC-GX7MK3 fw1.4 by flickering-star; the G97
is the same platform family -- Linux: zimage/rootfs/zboot/dtb -- and its `program`
is byte-for-byte the same size, 9,895,936, as the GX9 region below, so these are
the first addresses to try):

  Transport (GX9):  VID:PID 04da:2370, vendor interface class 0xff,
                    bulk OUT 0x01 (512), bulk IN 0x82 (512), int IN 0x83.
  Per-phase vendor control setup (8-byte setup packet, no data):
    before each OUT:  bmRequestType=0x40 bRequest=0 wValue=0 wIndex=0
    before each IN :  bmRequestType=0x40 bRequest=0 wValue=0 wIndex=1
  Read side: read ONE type/class byte, then the rest of the frame for that class.

  Frame classes -> total length: {0x08:16, 0x01:1030, 0x02:32774, 0x03:8198,
                                  0x04:4102, 0x05:106, 0x10:262}
  Generic frame: [0]=class [1]=seq(00) [2]=compl(ff) [3]=op [4..]=operands
                 [L-2]=checksum = sum(frame[1:L-2]) & 0xff   [L-1]=00

  Read ops:
    0x5c  1 KiB block read (class 0x01 request):
          [4:8]=LE start addr, [8:12]=LE exclusive end (must = start+1024).
          Reply class 0x01, op byte 0x05, 1024 data bytes at offset 4.
    0x9b  absolute 2-byte read: [4:8]=LE byte addr -> 2 data bytes.
    0x75  RAM-relative word read: [4:8]=LE index; addr = 0x80000000 + 2*index.
    0x35  indexed word read (settings): [4:6]=LE word index, [6]=selector.
  Write op:
    0x9c  absolute 2-byte write: [4:8]=LE addr, [8:10]=data. ACK = 0800ff01...

  GX9 landmarks (HYPOTHESES to test on G97, not guaranteed):
    program decrypted RAM : 0x83e80000 .. 0x847f0000  (len 0x970000)
    AES-128 key in image  : image off 0x8d0284  (runtime 0x84750284)
    update policy halfword: 0x83f1801a  (0=signed, 1=bypass)

SAFETY: addresses 0x40000000 and op 0x70 froze the GX9 (needed physical power
cycle). Start with a single 0x5c block read at 0x83e80000 and confirm it looks
like code before bulk-dumping. SD out, battery full. You accept the risk.
"""
import sys, struct, argparse, time

VID = 0x04da
CLASS_LEN = {0x08:16, 0x01:1030, 0x02:32774, 0x03:8198, 0x04:4102, 0x05:106, 0x10:262}

# GX9-derived hypotheses for the G97
PROGRAM_RAM_START = 0x83e80000
PROGRAM_RAM_LEN   = 0x970000      # == G97 `program` size
POLICY_ADDR       = 0x83f1801a

def _usb():
    try:
        import usb.core, usb.util
        return usb.core, usb.util
    except Exception as e:
        raise SystemExit("pyusb not available: %s\n  pip install pyusb (+libusb-1.0)" % e)

def _backend():
    """Use the bundled libusb from libusb-package so no manual DLL is needed."""
    try:
        import libusb_package
        return libusb_package.get_libusb1_backend()
    except Exception:
        return None

class Native:
    def __init__(self, vid=VID, pid=None):
        self.vid = vid
        self.pid = pid
        self._open(verbose=True)

    def _open(self, verbose=False):
        core, util = _usb()
        self.util = util
        be = _backend()
        dev = (core.find(idVendor=self.vid, backend=be) if self.pid is None
               else core.find(idVendor=self.vid, idProduct=self.pid, backend=be))
        if dev is None:
            raise SystemExit("camera not found (VID 0x%04x). In service mode? WinUSB bound?" % self.vid)
        self.dev = dev
        try: dev.set_configuration()
        except Exception: pass
        cfg = dev.get_active_configuration()
        self.ep_out = self.ep_in = None
        for intf in cfg:
            for ep in intf:
                d = util.endpoint_direction(ep.bEndpointAddress)
                t = util.endpoint_type(ep.bmAttributes)
                if t == util.ENDPOINT_TYPE_BULK and d == util.ENDPOINT_OUT and self.ep_out is None:
                    self.ep_out = ep
                if t == util.ENDPOINT_TYPE_BULK and d == util.ENDPOINT_IN and self.ep_in is None:
                    self.ep_in = ep
            if self.ep_out and self.ep_in:
                break
        if not (self.ep_out and self.ep_in):
            raise SystemExit("no bulk IN/OUT endpoints found")
        if verbose:
            print("device %04x:%04x  OUT 0x%02x  IN 0x%02x" %
                  (dev.idVendor, dev.idProduct, self.ep_out.bEndpointAddress, self.ep_in.bEndpointAddress))

    def recover(self):
        """USB-reset the dispatcher and re-open, to continue without a manual power-cycle."""
        try:
            self.dev.reset()
        except Exception:
            pass
        time.sleep(1.5)
        for _ in range(12):
            try:
                self._open(verbose=False)
                return True
            except SystemExit:
                time.sleep(0.5)
        return False

    def _setup(self, index):
        # vendor control setup, no data phase
        self.dev.ctrl_transfer(0x40, 0x00, 0x0000, index, None, timeout=3000)

    def _frame(self, cls, op, operands=b''):
        L = CLASS_LEN[cls]
        f = bytearray(L)
        f[0] = cls; f[1] = 0x00; f[2] = 0xff; f[3] = op
        f[4:4+len(operands)] = operands
        f[L-2] = sum(f[1:L-2]) & 0xff
        f[L-1] = 0x00
        return bytes(f)

    def _read_n(self, n, tmo, retries):
        """Read up to n bytes for the CURRENT IN phase (setup(1) already issued)."""
        buf = bytearray()
        empties = 0
        dl = time.time() + 6.0 + n / 20000.0
        while len(buf) < n and time.time() < dl:
            try:
                c = self.ep_in.read(n - len(buf), tmo).tobytes()
            except Exception:
                c = b''
            if c:
                buf += c; empties = 0
            else:
                empties += 1
                if empties >= retries:
                    break
        return bytes(buf)

    def cmd(self, cls, op, operands=b''):
        """Send one command; return (reply_class, reply_frame_bytes)."""
        self._setup(0)
        self.ep_out.write(self._frame(cls, op, operands), timeout=5000)
        # phase 1: one-byte type (own setup, retry for latency)
        t = b''
        dl = time.time() + 6.0
        while not t and time.time() < dl:
            self._setup(1)
            t = self._read_n(1, 800, 1)
        if not t:
            raise RuntimeError("no reply (type byte) for op 0x%02x" % op)
        rcls = t[0]
        L = CLASS_LEN.get(rcls, 16)
        # phase 2: full frame = ONE setup(1), then read to L (no re-setup mid-frame)
        self._setup(1)
        buf = self._read_n(L, 3000, 4)
        return rcls, buf

    def read_block(self, addr, size=1024):
        """0x5c block read -> `size` bytes (reply data at [4:4+size])."""
        rcls, r = self.cmd(0x01, 0x5c, struct.pack('<II', addr, addr + size))
        if len(r) >= 4 + size:
            return r[4:4+size]
        raise RuntimeError("short 0x5c reply: cls=0x%02x len=%d want>=%d head=%s" %
                           (rcls, len(r), 4 + size, r[:8].hex()))

    def read_block_n(self, addr, nbytes):
        """0x5c with a custom block length — probe whether G97 supports >1 KiB blocks.
        Returns (reply_class, full_reply_bytes)."""
        rcls, r = self.cmd(0x01, 0x5c, struct.pack('<II', addr, addr + nbytes))
        return rcls, r

    def read16(self, addr):
        """0x9b absolute 2-byte read."""
        rcls, r = self.cmd(0x08, 0x9b, struct.pack('<I', addr))
        return r[4:6] if len(r) >= 6 else b''

    def write16(self, addr, data2):
        """0x9c absolute 2-byte write. data2 = 2 bytes. Returns (class, frame)."""
        return self.cmd(0x08, 0x9c, struct.pack('<I', addr) + bytes(data2[:2]))

    def read_block_retry(self, addr, size=1024, tries=4):
        last = None
        for _ in range(tries):
            try:
                return self.read_block(addr, size)
            except Exception as e:
                last = e
                time.sleep(0.15)
        raise last

    def dump(self, start, length, outfile, resume=0, delay=0.0, blocksize=1024, progress=True):
        fo = open(outfile, 'r+b' if resume else 'wb')
        fo.seek(resume)
        n = resume
        resets = 0
        try:
            while n < length:
                blk = None
                try:
                    blk = self.read_block_retry(start + n)
                except Exception as e:
                    sys.stderr.write("\n  stalled at 0x%x (%s); USB reset-recovery #%d...\n" %
                                     (start + n, e, resets + 1))
                    resets += 1
                    if self.recover():
                        try:
                            blk = self.read_block_retry(start + n)
                        except Exception:
                            blk = None
                    if blk is None:
                        sys.stderr.write("STUCK at offset 0x%x. Power-cycle (battery out ~5s) + re-enter "
                                         "DISP+AF/AE LOCK, then:\n" % n)
                        sys.stderr.write("   py -3 lumix_native.py --dump 0x%x 0x%x %s --start 0x%x\n" %
                                         (start, length, outfile, n))
                        break
                fo.write(blk); fo.flush()
                n += len(blk)
                if delay:
                    time.sleep(delay)
                if progress and (n % (32*1024) == 0 or n >= length):
                    sys.stderr.write("\r  dumped %d / %d KiB  (resets:%d)" %
                                     (n//1024, length//1024, resets)); sys.stderr.flush()
        finally:
            fo.close()
        if progress:
            sys.stderr.write("\n")
        return n

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vid', type=lambda x:int(x,0), default=VID)
    ap.add_argument('--pid', type=lambda x:int(x,0), default=None)
    ap.add_argument('--probe', action='store_true',
                    help='single 0x5c block read at PROGRAM_RAM_START, hexdump it')
    ap.add_argument('--read16', type=lambda x:int(x,0), help='absolute 2-byte read at ADDR')
    ap.add_argument('--dump', nargs=3, metavar=('START','LEN','OUT'),
                    help='bulk 0x5c dump: START LEN OUTFILE (START/LEN accept hex)')
    ap.add_argument('--start', type=lambda x: int(x, 0), default=0,
                    help='resume a --dump from this byte offset into OUTFILE')
    ap.add_argument('--delay', type=float, default=0.0,
                    help='seconds to sleep between blocks (e.g. 0.03) to ease the dispatcher')
    ap.add_argument('--bigread', nargs=2, metavar=('ADDR', 'LEN'),
                    help='probe a single 0x5c read of LEN bytes at ADDR (test >1KiB blocks)')
    a = ap.parse_args()

    d = Native(a.vid, a.pid)

    if a.probe:
        blk = d.read_block(PROGRAM_RAM_START)
        print("block @0x%08x (%d bytes), first 64:" % (PROGRAM_RAM_START, len(blk)))
        print(" ", blk[:64].hex())
    if a.read16 is not None:
        print("[0x%08x] = %s" % (a.read16, d.read16(a.read16).hex()))
    if a.bigread:
        addr = int(a.bigread[0], 0); ln = int(a.bigread[1], 0)
        rcls, r = d.read_block_n(addr, ln)
        print("0x5c addr=0x%08x req_len=%d -> reply class 0x%02x, %d bytes total" %
              (addr, ln, rcls, len(r)))
        data = r[4:] if len(r) > 4 else b''
        print("  reply op 0x%02x; data bytes ~%d" % (r[3] if len(r) > 3 else -1, max(0, len(r) - 6)))
        print("  first 32:  %s" % data[:32].hex())
        if len(data) > 1040:
            print("  @1024-1056:%s   <-- data past 1 KiB means BIG read works" % data[1024:1056].hex())
        else:
            print("  (no data past 1 KiB -> capped at 1 KiB like GX9)")
    if a.dump:
        start = int(a.dump[0], 0); length = int(a.dump[1], 0); out = a.dump[2]
        got = d.dump(start, length, out, resume=a.start, delay=a.delay)
        print("wrote up to %d bytes to %s" % (got, out))

if __name__ == '__main__':
    main()
