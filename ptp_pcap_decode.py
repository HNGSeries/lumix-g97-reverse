#!/usr/bin/env python3
"""
ptp_pcap_decode.py - reconstruct PTP transactions from a USB capture of
LUMIX Tether / LUMIX Sync <-> camera traffic, so we can map the vendor protocol
(which opcodes Tether uses, their params, and the data it reads/writes).

Workflow:
  1. Capture with Wireshark + USBPcap while LUMIX Tether does its thing
     (connect, liveview, read settings, etc.). Filter to the camera's bulk
     endpoints.
  2. File > Export Packet Dissections > As JSON  (whole capture or selection).
  3. py -3 -I ptp_pcap_decode.py capture.json

It pulls each packet's usb.capdata, concatenates the bulk stream, and re-frames
PTP containers by their length field. For every container it prints:
  [CMD|DATA|RESP|EVENT] op=0x.... tid=.... params=[...] (+N data bytes: hex...)

This does not need scapy; it reads Wireshark's JSON export. If you'd rather feed
a raw hex stream (concatenated usb.capdata), use --hex file.
"""
import sys, json, struct, argparse

TYPES = {1: 'CMD ', 2: 'DATA', 3: 'RESP', 4: 'EVNT'}

def iter_capdata_from_wireshark_json(path):
    """Yield (direction_hint, bytes) for each packet carrying usb.capdata."""
    doc = json.load(open(path, encoding='utf-8'))
    for pkt in doc:
        try:
            layers = pkt['_source']['layers']
        except Exception:
            continue
        cap = None
        # usb.capdata may live under 'usb' or at top level depending on version
        for key in ('usb.capdata', 'usb.capdata_raw'):
            if key in layers:
                cap = layers[key]; break
        if cap is None and 'usb' in layers and isinstance(layers['usb'], dict):
            cap = layers['usb'].get('usb.capdata')
        if cap is None:
            continue
        if isinstance(cap, list):
            cap = cap[0]
        hexstr = cap.replace(':', '').replace(' ', '')
        try:
            yield bytes.fromhex(hexstr)
        except ValueError:
            continue

def reframe(stream):
    """Walk a concatenated bulk byte stream, yield PTP containers."""
    o = 0; n = len(stream)
    while o + 12 <= n:
        length, ctype, code, tid = struct.unpack_from('<IHHI', stream, o)
        if length < 12 or o + length > n:
            # desync: skip a byte and resync
            o += 1
            continue
        payload = stream[o+12:o+length]
        yield ctype, code, tid, payload
        o += length

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('capture', help='Wireshark JSON export, or --hex file')
    ap.add_argument('--hex', action='store_true', help='input is raw hex of concatenated usb.capdata')
    ap.add_argument('--maxdata', type=int, default=48, help='bytes of data phase to print')
    a = ap.parse_args()

    if a.hex:
        stream = bytes.fromhex(open(a.capture).read().split('#')[0].strip())
    else:
        stream = b''.join(iter_capdata_from_wireshark_json(a.capture))
    print("# %d bytes of bulk payload" % len(stream))

    vendor_ops = {}
    for ctype, code, tid, payload in reframe(stream):
        t = TYPES.get(ctype, '?%d' % ctype)
        # command/response params are u32s in the payload
        params = []
        if ctype in (1, 3):
            for i in range(0, len(payload) - 3, 4):
                params.append(struct.unpack_from('<I', payload, i)[0])
            extra = ''
        else:
            extra = ' +%d data: %s' % (len(payload), payload[:a.maxdata].hex())
        pstr = ' '.join('0x%x' % p for p in params) if params else ''
        print("%-4s op=0x%04x tid=%d %s%s" % (t, code, tid, pstr, extra))
        if ctype == 1 and code >= 0x9000:
            vendor_ops[code] = vendor_ops.get(code, 0) + 1

    if vendor_ops:
        print("\n# vendor opcodes seen (op: count):")
        for op, c in sorted(vendor_ops.items()):
            print("#   0x%04x : %d" % (op, c))

if __name__ == '__main__':
    main()
