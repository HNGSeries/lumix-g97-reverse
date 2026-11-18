#!/usr/bin/env python3
"""
lumix_decrypt.py - offline decryptor + key-finder, driven by the plaintext-SHA256
"oracle" in g97_v13_partitions.json.

Why an oracle: every UPD partition's stored SHA-256 is over the *plaintext*. So we
never have to guess blindly -- a key/mode is correct for a partition iff the
decrypted bytes hash to the stored digest.

Two uses (post RAM-dump):
  1. You recovered the 16-byte AES key (on GX9 it sat at program-image offset
     0x8d0284). Decrypt the whole .bin and verify:
       py -3 -I lumix_decrypt.py fw.bin --manifest g97_v13_partitions.json \
           --key <32hex> --mode cbc --out-dir plain/
  2. You have a RAM dump but not the exact key offset. Scan the dump for a 16-byte
     window that decrypts a small partition to its stored hash:
       py -3 -I lumix_decrypt.py fw.bin --manifest g97_v13_partitions.json \
           --find-key ram.bin --target dram_sleep

Cipher: GX9 used AES-128-CBC ("five-round" per the notes -- if standard 10-round
AES never matches the oracle, the cipher is a reduced-round/custom AES and this
tool's crypto backend must be swapped; the oracle logic stays the same). The
per-partition 12-byte nonce (UPD table +0x4C) is tried as CBC-IV (zero-padded)
and as a CTR nonce; --mode/--iv override.

Requires: pip install pycryptodome
"""
import sys, json, struct, hashlib, argparse, os

def _aes():
    try:
        from Crypto.Cipher import AES
        return AES
    except Exception as e:
        raise SystemExit("pycryptodome needed: %s\n  pip install pycryptodome" % e)

def load(fw, manifest):
    d = open(fw, 'rb').read()
    man = json.load(open(manifest))
    return d, man

def ct_of(d, p):
    fs = p['file_offset']; return d[fs:fs+p['size']]

def try_decrypt(AES, key, ct, mode, iv):
    if len(ct) == 0:
        return b''
    if mode == 'cbc':
        n = len(ct) - (len(ct) % 16)
        return AES.new(key, AES.MODE_CBC, iv[:16].ljust(16, b'\0')).decrypt(ct[:n])
    elif mode == 'ctr':
        from Crypto.Util import Counter
        ctr = Counter.new(128, initial_value=int.from_bytes(iv[:16].ljust(16, b'\0'), 'big'))
        return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(ct)
    elif mode == 'ecb':
        n = len(ct) - (len(ct) % 16)
        return AES.new(key, AES.MODE_ECB).decrypt(ct[:n])
    raise SystemExit("unknown mode " + mode)

def oracle_ok(pt, p):
    return hashlib.sha256(pt).hexdigest() == p['sha256_stored']

def iv_candidates(p, override):
    if override is not None:
        return [bytes.fromhex(override)]
    nonce = bytes.fromhex(p['nonce'])
    return [b'\x00'*16, nonce.ljust(16, b'\0'), (b'\x00'*4 + nonce)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firmware')
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--key', help='16-byte AES key (hex)')
    ap.add_argument('--mode', default='cbc', choices=['cbc','ctr','ecb'])
    ap.add_argument('--iv', help='explicit IV/nonce hex (else try nonce/zero)')
    ap.add_argument('--out-dir')
    ap.add_argument('--find-key', metavar='RAMDUMP', help='scan a RAM dump for the key')
    ap.add_argument('--target', default='dram_sleep', help='partition to test against oracle')
    ap.add_argument('--step', type=int, default=4, help='find-key scan step (bytes)')
    a = ap.parse_args()
    AES = _aes()
    d, man = load(a.firmware, a.manifest)
    parts = {p['name']: p for p in man['partitions']}

    if a.find_key:
        ram = open(a.find_key, 'rb').read()
        p = parts[a.target]
        ct = ct_of(d, p)
        if not ct:
            raise SystemExit("target %s has zero size; pick another --target" % a.target)
        print("scanning %d bytes of RAM for a key that decrypts '%s' (step %d, mode %s)..."
              % (len(ram), a.target, a.step, a.mode))
        for off in range(0, len(ram)-16, a.step):
            key = ram[off:off+16]
            for iv in iv_candidates(p, a.iv):
                try:
                    pt = try_decrypt(AES, key, ct, a.mode, iv)
                except Exception:
                    continue
                if oracle_ok(pt, p):
                    print("\nMATCH key @ram+0x%x = %s  iv=%s  mode=%s"
                          % (off, key.hex(), iv.hex(), a.mode))
                    return
            if off % (1<<20) == 0:
                sys.stderr.write("\r  @0x%x" % off); sys.stderr.flush()
        print("\nno key found (try --mode ctr, smaller --step, or a different --target)")
        return

    if not a.key:
        raise SystemExit("give --key, or use --find-key")
    key = bytes.fromhex(a.key)
    if a.out_dir: os.makedirs(a.out_dir, exist_ok=True)
    ok = 0
    for p in man['partitions']:
        ct = ct_of(d, p)
        best = None
        for iv in iv_candidates(p, a.iv):
            pt = try_decrypt(AES, key, ct, a.mode, iv)
            if oracle_ok(pt, p):
                best = (pt, iv); break
        tag = 'OK ' if best else '...'
        if best:
            ok += 1
            if a.out_dir:
                open(os.path.join(a.out_dir, "%02d_%s.bin" % (p['idx'], p['name'])),'wb').write(best[0])
        print("  [%s] %-11s size=%d iv=%s" %
              (tag, p['name'], p['size'], best[1].hex() if best else '-'))
    print("verified %d / %d partitions against the plaintext-SHA oracle" % (ok, len(man['partitions'])))

if __name__ == '__main__':
    main()
