"""Carve a SPURS policy module out of a PPU ELF and wrap it as an SPU ELF.

SPURS loads a policy module as raw bytes at LS 0xA00, so the PM is not an ELF
in the game image and extract_spu_images.py does not find it. The runtime
reports it at boot ("wid=N PM NOT LIFTED (fp=...)") with the pm= EA and size
cellSpursAddWorkload was given; pass those here. The wrapped ELF's text is
exactly those bytes, so build_spu_workloads.py registers the same fingerprint.

    python carve_pm.py game/EBOOT.elf analysis/spu/pm_wwsjob.elf 0x0075B200 11520

First used by MAG (Wws_Job PM at 0x019E4C80, 12032 B) and WipEout HD
(0x0075B200, 11520 B).
"""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wrap_spu_elf import wrap

LS_BASE = 0xA00

elf, out, vaddr, size = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), int(sys.argv[4], 0)
d = open(elf, "rb").read()
phoff, = struct.unpack_from(">Q", d, 0x20)
phnum, = struct.unpack_from(">H", d, 0x38)
for i in range(phnum):
    typ, _, off, pva, _, filesz = struct.unpack_from(">IIQQQQ", d, phoff + i * 56)
    if typ == 1 and pva <= vaddr and vaddr + size <= pva + filesz:
        raw = d[off + vaddr - pva:][:size]
        open(out, "wb").write(wrap(raw, base=LS_BASE, entry=LS_BASE))
        print(f"{out}: {size} bytes from 0x{vaddr:08X}, LS base 0x{LS_BASE:X}")
        break
else:
    sys.exit("PM range not inside any PT_LOAD")
