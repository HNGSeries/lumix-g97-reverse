# LUMIX G97 firmware RE — project record & handoff

Goal: decrypt / gain access to the Panasonic **Lumix DC-G97** (model code **MC3241**)
firmware. Source image: `G97__V13.bin` (fw V1.3, UPD container). Camera on hand runs
fw **1.12**.

> **Disclaimer.** Independent, non-commercial reverse-engineering of my own camera for
> interoperability and education. **No Panasonic firmware images or proprietary binaries
> are included** (`.gitignore` keeps them out). Service-mode access and RAM writes can
> **brick** a camera — use entirely at your own risk.

## TL;DR status (2026-11-18)

**✅ DONE — reproducible deep access:** we enter the camera's service USB mode, bind
WinUSB, speak its native dispatcher protocol, and **read the camera's DECRYPTED RAM
at any address** (confirmed decrypted ARM Thumb-2 code). This is the hard part, and
it is further than the public modern-Lumix scene has gone on this body.

**🧱 BLOCKED — full decryption not achieved:**
1. The service dispatcher **dies after only ~40-46 reads per session** and only a
   physical power-cycle resets it, so dumping the 9.4 MB program (≈9600 reads) is
   impractical (~215 power-cycles).
2. The AES **key offset is unknown on G97** — the GX9 locations don't transfer
   (see below).
3. The cipher may be a non-standard **5-round AES-128-CBC**, so even the key may
   need a custom decryptor.

We chose to **consolidate** here. Everything needed to resume is below.

---

## The working method (reproducible)

### 1. Enter service USB mode
On the camera: insert an SD card with at least one photo, mode dial to **P**, power
**OFF**, then power **ON while holding `DISP` + `AF/AE LOCK`**. The screen may look
normal/blank — that's expected (it's a headless USB mode, not a menu).

> A *different* combo — power on holding `Playback`+`AF/AE LOCK`, then hold
> `Playback`+`MENU/SET` and tap `Left` ×2 — opens the **CAMERA INFO** diagnostic
> screen (shutter count / error log). That mode is **info-only and exposes NO USB**.
> The decryption path needs the `DISP`+`AF/AE LOCK` mode.

### 2. Bind WinUSB (Windows)
Plug USB. Device Manager shows **"DC-G97"** under *Other devices*,
`USB\VID_04DA&PID_2370`, **Code 28** (no driver). Run **Zadig**
(https://zadig.akeo.ie) → Options → List All Devices → select **DC-G97** → **WinUSB**
→ **Install Driver** (not Replace). Reversible via Device Manager → Uninstall.

### 3. Talk to it
Deps: `pip install pyusb libusb-package` (they land in *user* site-packages, so run
the tools with **`py -3`**, NOT `py -3 -I`, which hides user site). Confirm:
```
py -3 lumix_scan.py --04da     # -> 04da:2370 [ff/a0/b0] *** VENDOR SERVICE ***
py -3 lumix_native.py --read16 0x80208000   # -> fe2b  (matches GX9)
py -3 lumix_native.py --probe                # -> 1024 bytes of decrypted RAM @0x83e80000
```

### The native dispatcher protocol (reverse-engineered, WORKS)
- Transport: VID:PID **04da:2370**, vendor interface class **ff/a0/b0**, bulk **OUT
  0x01**, bulk **IN 0x82**, interrupt IN 0x83.
- Command = 16-byte **class-8 frame**: `[08][00][ff][op][operands…][sum(bytes1-13)&0xff][00]`.
- **Vendor control setup before EVERY phase** (the key that made it work):
  `ctrl_transfer(0x40,0,0,0)` before the bulk OUT; `ctrl_transfer(0x40,0,0,1)`
  before **each** bulk IN read.
- Reply arrives as a **1-byte type** (one IN read) then the **full frame** (next IN
  read) — each with its own `setup(1)`.
- Ops confirmed: **`0x9b`** absolute 2-byte read (addr LE @[4:8]; reply op `0x36`,
  data @[4:6]). **`0x5c`** 1 KiB block read (class-01 1030-byte request: start LE
  @[4:8], end=start+1024 @[8:12]; reply class-01 op `0x05`, 1024 data bytes @[4:1028]).
  **`0x9c`** absolute 2-byte write (addr @[4:8], data @[8:10]) — RAM write works.
- **Hazard:** a command left half-read, or any unanswered command, **hangs the
  dispatcher** → power-cycle (battery out ~5 s) to reset. GX9 notes also warn op
  `0x70` and addr `0x40000000` froze the camera — avoid.

### Confirmed facts
- `0x9b @0x80208000` → `fe2b` = **identical to GX9** → the G97 RAM map ≈ GX9.
- RAM `0x84750200`+ is **decrypted ARM Thumb-2** (`push/pop/mov/bl/movw`).
- Program image lives at **0x83e80000 .. 0x847f0000** (0x970000 = 9.4 MB = the
  `program` partition size). RAM `0x05ed1800`+ holds float calibration tables.

---

## The walls (what blocks full decryption)

- **Dispatcher longevity:** dies at ~9 reads (no delay) / 34 (`--delay 0.03`) / 46
  (`--delay 0.15`) — plateaus; `dev.reset()` does not revive it; physical
  power-cycle required. `lumix_native.py --dump` supports `--start <off>` to resume,
  but ~215 power-cycles for the full program is impractical. (flickering-star got
  ~1900 reads/session on GX9 with the *same* protocol → G97 is far flakier; likely a
  firmware watchdog we can't reach from the host.)
- **Key offset unknown on G97:** GX9's key at image offset `0x8d0284` (=RAM
  `0x84750284`) is **code** on G97; GX9's runtime copy `0x05ed1c28` is **float data**
  on G97. Both shifted with fw version (G97 1.12 vs GX9 1.4).
- **Cipher:** possibly **5-round AES-128-CBC** (per GX9 docs) → `lumix_decrypt.py`
  (standard 10-round AES) may not validate even with the right key.

## If/when resuming — options
1. **Grind a targeted dump:** `--dump` a region likely to hold the key (around the
   GX9 offset, e.g. `0x84700000`–`0x84770000`) in ~45-read chunks with `--start`
   resume across power-cycles, then `lumix_decrypt.py --find-key` (oracle =
   plaintext SHA-256 in `g97_v13_partitions.json`). Tedious; also needs the cipher
   question settled.
2. **Custom firmware without decrypting:** we can **write RAM (`0x9c`)**; find the
   G97 **update-policy flag** (GX9 `0x83f1801a`, 0=signed/1=bypass-ECDSA), set it,
   then drive the SD firmware-update path to flash modified/unsigned firmware. Also a
   research tail (find the G97 policy addr + the flash trigger).
3. **Fix dispatcher longevity:** root-cause the ~45-read death (USB analyzer /
   different pacing / keep-camera-awake) to enable a real dump.

### SOFTWARE PATH EXHAUSTED — the dispatcher crash is unfixable from the host
Tested (2026-11-18): word-read `0x9b` crashes the same as `0x5c` (~61 reads);
interrupt-endpoint (`0x83`) drain made it WORSE (32); delay/`dev.reset()` don't
help. The ~40-75-command crash is fundamental G97 firmware behaviour. **USB is
capped at ~60 commands per power-cycle** — fine for a handful of KNOWN addresses,
but every version-specific target (key, policy) is shifted off the GX9 map and we
can't dump-and-search 9.4 MB. So a full image needs **HARDWARE** (bypasses the
dispatcher):
- **UART console** — find TX/RX/GND test points on the mainboard, 3.3 V USB-UART;
  least invasive; may give a boot log / shell / flash access.
- **SPI-NOR in-circuit** — if boot/firmware is on a SOIC-8 NOR, a SOIC clip +
  CH341A + `flashrom` reads it without desoldering.
- **eMMC / NAND chip-off** — desolder the main flash, read with an eMMC/NAND
  programmer; most reliable for the full image.
- **Open question for all:** is the on-flash firmware encrypted at rest (→
  ciphertext, still need the key) or plaintext (→ full win)? Unknown until tried.
  (GX9's plaintext came from RAM; GM5 did a 32 MiB NOR backup → may be readable.)

## Tools in this folder
| file | what |
|---|---|
| `lumix_scan.py` | read-only USB enumerator (`--04da`, `--watch`); spots 04da:2370 ff/a0/b0 |
| `lumix_native.py` | the native dispatcher client: `--read16`, `--probe`, `--dump START LEN OUT [--start OFF] [--delay S]`, `--write16` |
| `lumix_try.py` | single clean class-8 command (debugging the protocol) |
| `lumix_diag.py` | transport/handshake matrix prober |
| `pana_unpack.py` | parse/verify the UPD .bin, extract partitions, `--json` manifest |
| `lumix_decrypt.py` | offline decryptor + oracle key-finder (standard AES; may need 5-round variant) |
| `g97_v13_partitions.json` | 37-partition manifest incl. **plaintext SHA-256 = decrypt oracle** |
| `lumix_usb_probe.py`, `ptp_pcap_decode.py` | PTP-tether tooling (dead end on G97 — no PTP mode) |

Dumped samples: `program.bin` (~46 KB @0x83e80000), `keycopy.bin` (4 KB @0x05ed1800).

## Reference
- Repos: `flickering-star/lumix-firmware-research` (GX9 — the protocol template),
  `ShaoCI-Hz/lumix-fullframe-reverse` (S5M2 UPD format), `williamwu1234/lumix-s1m2-research`.
- SoC: Panasonic Venus Engine (MN103 family). UPD container: magic `UPD\0`, CRC32
  @0x40, ECDSA P-256 sig @0x220, 58-slot partition table @0x2EC.
