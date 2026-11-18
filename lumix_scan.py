#!/usr/bin/env python3
"""
lumix_scan.py - passive, READ-ONLY USB enumerator for finding how a camera shows
up (no open, no commands, no WinUSB needed). Safe to run repeatedly.

Modes:
  (no args)   list ALL currently-connected USB devices (every VID), flagging
              Panasonic (04da) and any vendor service interface (class ff/a0/b0).
  --watch     poll continuously and print when any device appears/disappears -
              use this to catch a service/adjustment device that enumerates under
              a NON-Panasonic VID or only briefly (the "2 connect sounds" case).
  --04da      only show Panasonic devices (the old behavior).

Known Panasonic PIDs:
  0x2372 PC(Storage)/MSC  |  0x2382 PTP/Tether  |  0x2370 SERVICE/native dispatcher
A service/adjustment mode may instead appear under the SoC's own VID (not 04da),
so --watch shows everything.
"""
import sys, time
PIDS = {0x2372: 'PC(Storage)/MSC', 0x2382: 'PTP/Tether',
        0x2370: 'SERVICE/native dispatcher'}
try:
    import libusb_package, usb.util
except Exception as e:
    raise SystemExit("need pyusb+libusb-package: pip install pyusb libusb-package (%s)" % e)

def classes_of(d):
    cl = []
    try:
        for cfg in d:
            for i in cfg:
                cl.append((i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol))
    except Exception:
        pass
    return tuple(cl)

def snapshot():
    out = set()
    for d in libusb_package.find(find_all=True):
        out.add((d.idVendor, d.idProduct, classes_of(d)))
    return out

def fmt(dev):
    vid, pid, classes = dev
    cl = ' '.join('%02x/%02x/%02x' % c for c in classes) or '-'
    tag = ''
    if vid == 0x04da:
        tag += '  <PANASONIC %s>' % PIDS.get(pid, 'PID?')
    if any(c[0] == 0xff and c[1] == 0xa0 and c[2] == 0xb0 for c in classes):
        tag += '  *** VENDOR SERVICE ff/a0/b0 -- THE ONE ***'
    elif any(c[0] == 0xff for c in classes) and vid != 0x04da:
        tag += '  <vendor-class device, note this VID:PID>'
    return '%04x:%04x  [%s]%s' % (vid, pid, cl, tag)

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ''
    if arg == '--04da':
        devs = [d for d in snapshot() if d[0] == 0x04da]
        if not devs:
            print('no Panasonic (04da) device connected.')
        for d in sorted(devs):
            print(fmt(d))
        return
    if arg == '--watch':
        print('watching USB (Ctrl-C to stop).')
        print('==> now do the service combo and plug/unplug USB; changes print below.')
        prev = snapshot()
        print('baseline: %d USB devices present.' % len(prev))
        try:
            while True:
                cur = snapshot()
                for d in sorted(cur - prev):
                    print(time.strftime('%H:%M:%S'), ' +APPEARED ', fmt(d))
                for d in sorted(prev - cur):
                    print(time.strftime('%H:%M:%S'), ' -gone     ', fmt(d))
                prev = cur
                time.sleep(0.3)
        except KeyboardInterrupt:
            print('\nstopped.')
        return
    # default: list everything
    devs = sorted(snapshot())
    print('%d USB devices:' % len(devs))
    for d in devs:
        print('  ' + fmt(d))
    if not any(d[0] == 0x04da or any(c[0] == 0xff for c in d[2]) for d in devs):
        print('(no Panasonic and no vendor-class device seen right now)')

if __name__ == '__main__':
    main()
