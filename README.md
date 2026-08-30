  # reCAPTCHA v3 client research — teardown
  
  Companion material for a write-up on a from-scratch reCAPTCHA v3 /reload client
  (Rust). The conclusion: the wall is server-side. The client-side behavioral-signal
  diversity — the part everyone assumes is the weak point at volume — is measurably
  healthy; what gates validity is the Google-encrypted token core, which no client
  can forge. The full client isn't public; this repo holds the pieces that back the
  claims and let others reproduce the key measurement.
  
  ## Contents
  - POST.md — the write-up (markdown).
  - scripts/field16_cipher.py — field "16" cipher: decrypt + re-encrypt (stream
    cipher, key = anchor timestamp). Round-trip self-test: python3 scripts/field16_cipher.py
  - scripts/hf_dissect.py — dissects the HF token; python3 scripts/hf_dissect.py scripts/sample_hf_tokens.txt
  - scripts/sample_hf_tokens.txt — 19 real HF tokens from one session.
  - scripts/diversity_oracle.py — compares how much decrypted /reload registries
    vary each slot vs real browser sessions; only trusts raw/cleartext slots
    (encrypted probe payloads re-mask per session, so their ciphertext always
    "varies" — a trap). Baseline: the fingerprint captures in elyelysiox/recaptcha.
    python3 scripts/diversity_oracle.py --real /path/to/recaptcha/fingerprint
  - images/ — screenshots referenced by the write-up.
  
  ## Shown vs not
  Shown: mechanisms verifiable from public data + the measurement method. Not shown:
  the full Rust client, device profiles, transport relay.
