#!/usr/bin/env python3
"""reCAPTCHA v3 — field "16" cipher (stream cipher, not AES).

Key = anchor timestamp mod 256. A captured field-16 blob is useless on a fresh
anchor unless you decrypt it and re-encrypt it with the new key. That's exactly
what these two functions do.

    body  = base64url-decoded field, WITHOUT the leading '0' prefix
    alea  = one fresh random byte, placed at the head
    plaintext = a JSON registry (79 slots), always starts with '['

Round-trip demo:
    python3 field16_cipher.py
"""
import json

def decrypt16(body):
    """Return (key, alea, plaintext). Key found by brute force (256 tries);
    the plaintext is a JSON registry, so we confirm each candidate parses."""
    alea = body[0]
    length = len(body) - 1
    for key in range(256):
        pt = bytes((body[1 + i] - length - (key + alea) * (i + alea)) % 256
                   for i in range(length))
        if pt[:1] == b'[':
            try:
                json.loads(pt)          # real plaintext is valid JSON
            except ValueError:
                continue
            return key, alea, pt
    return None

def encrypt16(pt, key, alea):
    n = len(pt)
    return bytes([alea]) + bytes((pt[i] + n + (key + alea) * (i + alea)) % 256
                                 for i in range(n))

if __name__ == "__main__":
    # self-test on a realistic registry: encrypt, then recover it blind
    plaintext = json.dumps(
        ["ua", 1440, 900, 24, "en-US", None, "webgl-vendor", [1, 2, 3],
         "canvas-hash", 0, 1, "tz", -60, True, "plugins", []],
        separators=(',', ':')).encode()
    key, alea = 137, 88
    ct = encrypt16(plaintext, key, alea)
    k2, a2, pt2 = decrypt16(ct)
    print("plaintext in :", plaintext.decode())
    print("key/alea     :", key, alea)
    print("recovered key:", k2, " alea:", a2)
    print("recovered pt :", pt2.decode())
    print("round-trip OK:", pt2 == plaintext and k2 == key)
