#!/usr/bin/env python3
"""reCAPTCHA v3 — HF token dissector.

The short "HF..." token returned by grecaptcha.enterprise.execute() (no /reload,
produced locally in a few ms) has this layout once base64url-decoded (N bytes):

    byte 0        = 0x1c            (type, constant)
    byte 1        = counter         (changes every call)
    bytes 2..4    = 3-byte XOR key  (in the clear)
    bytes 5..N-2  = payload, masked with a period-3 XOR using that key
    byte N-1      = trailing byte   (varies)

Unmask the payload and the CORE is byte-for-byte identical between two calls in
the SAME session. Each execute() just re-wraps the same encrypted core with a
fresh counter/key/trailer.

Usage:
    python3 hf_dissect.py tokens.txt        # one HF token per line
    python3 hf_dissect.py HFxxxx HFyyyy ...  # tokens as args
"""
import base64, hashlib, sys

def core_of(tok):
    raw = base64.urlsafe_b64decode(tok.strip() + "=" * (-len(tok.strip()) % 4))
    key = raw[2:5]
    core = bytes(raw[5 + i] ^ key[i % 3] for i in range(len(raw) - 6))
    return raw, key, core

def main(argv):
    if len(argv) == 2 and not argv[1].startswith("HF"):
        toks = [l.strip() for l in open(argv[1]) if l.strip()]
    else:
        toks = argv[1:]
    if not toks:
        print(__doc__); return
    seen = {}
    for i, t in enumerate(toks):
        raw, key, core = core_of(t)
        sha = hashlib.sha256(core).hexdigest()[:12]
        seen.setdefault(sha, []).append(i)
        print(f"[{i:2}] len={len(raw)} byte0={raw[0]:#04x} counter={raw[1]:3} "
              f"key={key.hex()} trailer={raw[-1]:3} core_sha={sha}")
    print(f"\n{len(toks)} tokens, {len(seen)} distinct core(s).")
    if len(seen) == 1:
        print("=> single encrypted core, re-wrapped every call (same session).")

if __name__ == "__main__":
    main(sys.argv)
