**Title:** Rebuilt Google's reCAPTCHA v3 client in Rust — and measured that the wall is 100% server-side

---

Been doing this solo for a few weeks: rebuilding the reCAPTCHA v3 `/reload` client from scratch in Rust, no browser in the
loop. This isn't a "help me" post — I hit a conclusion I can back with a measurement, and I want to compare notes with
people who've been in the same trenches.

**What I built**

- Deobfuscated the client across 4 releases; every `/reload` field sorted into fixed / release-tied / client-tied / 
session-tied.
- 279 parity tests against the real JS. The anchor matches a real Chrome exactly; a pre-warmed transport gets the token to
its real size.
- Cracked the central encrypted field ("16") — I can decrypt AND re-encrypt it with my own key (stream cipher, key = 
anchor timestamp). A captured blob is dead on a fresh anchor unless you re-key it.
- ~10% of tokens replayed from a fresh capture pass a real login.

**The part I was sure was my weak point — and wasn't**

The body carries ~50 behavioral/environment slots (canvas, webgl, DOM hashes, active element, timings, storage, screen, UA
data). I assumed they'd be too uniform at volume. So I measured — against the real decrypted registries in the 
elyelysiox/recaptcha repo, slot by slot.

One trap worth flagging: the probe payloads are re-encrypted per session, so comparing the ciphertext fakes a "everything 
varies." You have to compare only the raw/cleartext slots. Once corrected, the verdict was clean: my diversity is healthy 
— I vary the same slots a real browser varies, and hold constant the ones it holds constant. The "uniform at volume" 
problem only showed up when I froze the RNG seed for a reproducible run; in volume mode (fresh session + a pool of real 
device profiles) it already looks like real traffic.

**So where's the wall?**

Entirely server-side. The token core is encrypted by Google, session-bound, not forgeable client-side. Validity is a
server roll, and ~10% is likely the ceiling for replay — not a client bug I can engineer away.

**Two technical bits**

Field 16 cipher — stream cipher (not AES), key = anchor timestamp mod 256:

```python
def decrypt16(body):                # base64url-decoded field, leading '0' removed
    alea = body[0]; n = len(body) - 1
    for key in range(256):          # key brute-forced in 256 tries
        pt = bytes((body[1+i] - n - (key+alea)*(i+alea)) % 256 for i in range(n))
        if pt[:1] == b'[':          # plaintext is a JSON registry -> starts with '['
            return key, alea, pt

def encrypt16(pt, key, alea):
    n = len(pt)
    return bytes([alea]) + bytes((pt[i] + n + (key+alea)*(i+alea)) % 256 for i in range(n))
```

HF token layout — decode base64url (N bytes): byte 0 = 0x1c, byte 1 = counter, bytes 2-4 = 3-byte XOR key in the clear,
bytes 5..N-2 = payload masked with a period-3 XOR, byte N-1 = trailer. Unmask it and the core is byte-for-byte identical
between calls in one session — one single core across 19 tokens in a row.

Open questions — comparing notes, not asking for a fix:

- Is ~10% the ceiling for replay-at-scale, or is someone doing better?
- Does the backend score cross-signal coherence over individual signals?
- Any client lever left (freshness window, harvesting real rc::a, warm transport), or is it all in the encrypted core now?
- Has anyone mapped how the server weights these signals?
