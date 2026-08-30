#!/usr/bin/env python3
"""Diversity oracle - measure whether a set of reCAPTCHA v3 /reload registries
varies its fingerprint slots like real browser sessions do.

The /reload body carries a ~79-slot registry (field "16"). Slots 27..78 are
behavioral/environment probes. The question this answers: does your generated
traffic vary the same slots a real browser varies between sessions?

THE ONE LESSON BAKED IN: most probe slots carry a per-session RE-ENCRYPTED
payload, so their ciphertext changes every session even when the plaintext is
constant. Comparing ciphertext gives a fake "everything varies." So this tool
only compares the raw / cleartext slots, where the comparison is meaningful:

    4, 5, 16, 17, 18, 64, 66, 69, 72, 73, 75

Usage:
    # just show what real sessions vary (clone elyelysiox/recaptcha for fp data):
    python3 diversity_oracle.py --real /path/to/recaptcha/fingerprint

    # compare your own DECRYPTED registries against the real baseline:
    python3 diversity_oracle.py --real /path/to/fingerprint --mine /path/to/mine

Each file in --real / --mine is a JSON array = one decrypted registry.
"""
import json, glob, os, argparse

VALID = [4, 5, 16, 17, 18, 64, 66, 69, 72, 73, 75]

def value(x):
    # probe slots are [value, signal, duration]; keep only the value part
    if isinstance(x, list) and len(x) == 3 and isinstance(x[1], (int, float)):
        return x[0]
    return x

def load(dir_):
    regs = []
    for f in sorted(glob.glob(os.path.join(dir_, "*.json"))):
        try:
            regs.append(json.load(open(f)))
        except Exception:
            pass
    return regs

def distinct(regs, s):
    vs = [value(r[s]) for r in regs if s < len(r) and r[s] is not None]
    return len(set(json.dumps(v, ensure_ascii=False) for v in vs)), len(vs)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", required=True, help="dir of real decrypted registries (fp*.json)")
    ap.add_argument("--mine", help="dir of your own decrypted registries")
    a = ap.parse_args()

    real = load(a.real)
    mine = load(a.mine) if a.mine else None
    if not real:
        print("no real registries found in", a.real); return

    print(f"real sessions: {len(real)}" + (f" | mine: {len(mine)}" if mine else ""))
    print("(comparing only raw/cleartext slots - ciphertext slots always 'vary')\n")
    header = f"{'slot':>4} | {'real dist/n':>12}"
    if mine:
        header += f" | {'mine dist/n':>12} | verdict"
    print(header)
    print("-" * (len(header) + 2))

    frozen = []
    for s in VALID:
        rd, rn = distinct(real, s)
        line = f"{s:>4} | {rd:>5}/{rn:<6}"
        if mine:
            md, mn = distinct(mine, s)
            v = ""
            if rd > 1 and md == 1 and mn > 0:
                v = "<< FROZEN (real varies)"; frozen.append(s)
            line += f" | {md:>5}/{mn:<6} | {v}"
        print(line)
    if mine:
        print(f"\nslots you freeze but real sessions vary: {frozen or 'none'}")

if __name__ == "__main__":
    main()
