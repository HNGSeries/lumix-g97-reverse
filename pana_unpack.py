#!/usr/bin/env python3
"""
pana_unpack.py - Panasonic LUMIX UPD firmware unpacker (G97 / S5M2-generation format)

Parses the UPD container, verifies the header CRC32, extracts the ECDSA P-256
signature, walks the 58-slot partition table, and dumps each partition's (still
encrypted) payload. For every partition it also computes SHA-256 of the ciphertext
and compares it to the stored digest -- this tells us whether the stored hash is
over ciphertext (integrity/oracle useful now) or over plaintext (a decryption
oracle for later).

Container layout (offsets absolute unless noted):
  0x000  "UPD\0"
  0x004  u32  block size (512)
  0x00C  16B  model id ("MC3241")
  0x03C  u32  image_data_size (= filesize - 512)
  0x040  u32  CRC32 over data[0x200:]
  0x200  "panasonic" tag
  0x220  64B  ECDSA P-256 signature (r||s)
  0x2A0  second, identical UPD record
  0x2EC  partition table: up to 58 entries x 92 bytes, name-first:
           +0x00 name   13B (nul-padded)
           +0x0D tag     3B
           +0x10 u32 size
           +0x14 u32 offset   (into image data, i.e. file offset 0x200 + offset)
           +0x18 u32 flags
           +0x1C sha256 32B
           +0x3C nonce  12B
           +0x48 trailing 20B

Usage:
  py -3 -I pana_unpack.py <firmware.bin> --list
  py -3 -I pana_unpack.py <firmware.bin> --extract --out-dir <dir>
  py -3 -I pana_unpack.py <firmware.bin> --extract program --out-dir <dir>
"""
import sys, os, struct, zlib, hashlib, math, json, argparse

HDR = 0x200
TABLE = 0x2EC
ENTRY = 92
MAXENT = 58

def entropy(b):
    if not b:
        return 0.0
    c = [0]*256
    for x in b:
        c[x] += 1
    e = 0.0; L = len(b)
    for v in c:
        if v:
            p = v/L; e -= p*math.log2(p)
    return e

def parse(path):
    d = open(path, 'rb').read()
    n = len(d)
    magic = d[0:4]
    if magic != b'UPD\x00':
        raise SystemExit("not a UPD image (magic=%r)" % magic)
    block = struct.unpack_from('<I', d, 0x04)[0]
    model = d[0x0C:0x1C].split(b'\x00')[0].decode('latin1')
    image_data_size = struct.unpack_from('<I', d, 0x3C)[0]
    crc_stored = struct.unpack_from('<I', d, 0x40)[0]
    crc_calc = zlib.crc32(d[HDR:]) & 0xffffffff
    tag = d[0x200:0x209]
    sig = d[0x220:0x260]  # ECDSA P-256 r||s

    hdr = {
        'file': os.path.basename(path), 'filesize': n,
        'block_size': block, 'model': model,
        'image_data_size': image_data_size,
        'crc32_stored': '0x%08x' % crc_stored,
        'crc32_calc':   '0x%08x' % crc_calc,
        'crc32_ok': crc_stored == crc_calc,
        'panasonic_tag': tag.decode('latin1', 'replace'),
        'ecdsa_p256_r': sig[:32].hex(),
        'ecdsa_p256_s': sig[32:].hex(),
    }

    parts = []
    for i in range(MAXENT):
        off = TABLE + i*ENTRY
        if off + ENTRY > n:
            break
        name = d[off:off+13].split(b'\x00')[0]
        if not name or not all(32 <= c < 127 for c in name):
            continue
        size   = struct.unpack_from('<I', d, off+0x10)[0]
        poff   = struct.unpack_from('<I', d, off+0x14)[0]
        flags  = struct.unpack_from('<I', d, off+0x18)[0]
        sha    = d[off+0x1C:off+0x3C]
        nonce  = d[off+0x3C:off+0x48]
        fstart = HDR + poff
        payload = d[fstart:fstart+size]
        ct_sha = hashlib.sha256(payload).digest()
        parts.append({
            'idx': i, 'name': name.decode('latin1'),
            'tag': d[off+0x0D:off+0x10].hex(),
            'size': size, 'file_offset': fstart,
            'flags': flags,
            'sha256_stored': sha.hex(),
            'sha256_ciphertext': ct_sha.hex(),
            'sha_matches_ciphertext': ct_sha == sha,
            'nonce': nonce.hex(),
            'entropy': round(entropy(payload[:1<<20]), 4),  # sample first 1 MiB
        })
    return d, hdr, parts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--extract', nargs='?', const='*', default=None,
                    help="extract all, or a named partition")
    ap.add_argument('--out-dir', default='out')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    d, hdr, parts = parse(a.firmware)

    if a.json:
        print(json.dumps({'header': hdr, 'partitions': parts}, indent=2))
        return

    print("== HEADER ==")
    for k, v in hdr.items():
        print("  %-18s %s" % (k, v))
    tot = sum(p['size'] for p in parts)
    print("\n== PARTITIONS (%d) ==  total payload %d bytes (%.1f MB)" %
          (len(parts), tot, tot/1048576))
    print("  %-11s %10s %10s %6s %5s %-5s %s" %
          ("name","size","file_off","flags","ent","shaCT","nonce[:8]"))
    for p in parts:
        print("  %-11s %10d 0x%08x %6d %5.2f %-5s %s" % (
            p['name'], p['size'], p['file_offset'], p['flags'],
            p['entropy'], 'Y' if p['sha_matches_ciphertext'] else 'n',
            p['nonce'][:16]))

    if a.extract is not None:
        os.makedirs(a.out_dir, exist_ok=True)
        sel = [p for p in parts if a.extract == '*' or p['name'] == a.extract]
        for p in sel:
            fs = p['file_offset']
            blob = d[fs:fs+p['size']]
            fn = os.path.join(a.out_dir, "%02d_%s.enc" % (p['idx'], p['name']))
            open(fn, 'wb').write(blob)
            print("  wrote %s (%d bytes)" % (fn, len(blob)))

if __name__ == '__main__':
    main()
