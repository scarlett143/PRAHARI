"""Measure the cryptographic operations this system actually performs.

Run from `backend/` with `PYTHONPATH=.`. On the deployment host wrap it in a CPU cap --
`systemd-run --scope -p CPUQuota=40% -- nice -n 19 …` -- because the box is shared and a
benchmark is by definition the most CPU-hungry thing that will run on it that day.

Numbers are per-operation medians. Medians rather than means because a single scheduler
preemption on a loaded shared host skews a mean badly and tells you nothing about the
operation itself.
"""
from __future__ import annotations

import statistics
import time


def bench(label: str, fn, rounds: int = 50) -> dict:
    # One untimed call first: the first invocation pays for lazy imports and any one-time
    # table setup, which is not what anyone is trying to measure.
    fn()
    samples = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return {
        "label": label,
        "median_ms": statistics.median(samples),
        "min_ms": min(samples),
        "rounds": rounds,
    }


def main() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from app.crypto import hybrid, pqc, pqsign
    from app import security

    results: list[dict] = []
    backend = pqc.get_backend()
    results.append({"label": f"PQC backend: {backend.name}", "median_ms": None, "min_ms": None, "rounds": 0})

    # -- ML-KEM-768 (FIPS 203) ------------------------------------------------
    kp = backend.keygen()
    results.append(bench("ML-KEM-768 keygen", backend.keygen))
    # `encapsulate` returns (ciphertext, shared_secret).
    ciphertext, _ = backend.encapsulate(kp.encapsulation_key)
    results.append(bench("ML-KEM-768 encapsulate", lambda: backend.encapsulate(kp.encapsulation_key)))
    results.append(
        bench("ML-KEM-768 decapsulate", lambda: backend.decapsulate(kp.decapsulation_key, ciphertext))
    )

    # -- Classical halves of the hybrid --------------------------------------
    x_priv = X25519PrivateKey.generate()
    x_pub = X25519PrivateKey.generate().public_key()
    results.append(bench("X25519 keygen", X25519PrivateKey.generate))
    results.append(bench("X25519 shared secret", lambda: x_priv.exchange(x_pub)))

    # -- The full hybrid handshake, which is what a session actually costs ----
    pub, priv = hybrid.generate_bundle()
    results.append(bench("Hybrid bundle keygen (X25519 + ML-KEM-768)", hybrid.generate_bundle, rounds=25))
    results.append(bench("Hybrid initiate (encap + HKDF)", lambda: hybrid.initiate(pub), rounds=25))
    ct, _ = hybrid.initiate(pub)
    results.append(bench("Hybrid respond (decap + HKDF)", lambda: hybrid.respond(priv, pub, ct), rounds=25))

    # -- Signatures -----------------------------------------------------------
    ed = Ed25519PrivateKey.generate()
    message = b"prahari benchmark message"
    ed_sig = ed.sign(message)
    results.append(bench("Ed25519 sign", lambda: ed.sign(message)))
    results.append(bench("Ed25519 verify", lambda: ed.public_key().verify(ed_sig, message)))

    if pqsign.available():
        pq_pub, pq_sec = pqsign.generate_keypair()
        pq_sig = pqsign.sign(pq_sec, message)
        results.append(bench("ML-DSA-65 keygen", pqsign.generate_keypair, rounds=25))
        results.append(bench("ML-DSA-65 sign", lambda: pqsign.sign(pq_sec, message), rounds=25))
        results.append(bench("ML-DSA-65 verify", lambda: pqsign.verify(pq_pub, message, pq_sig), rounds=25))
    else:
        results.append({"label": "ML-DSA-65: liboqs unavailable", "median_ms": None, "min_ms": None, "rounds": 0})

    # -- Symmetric ------------------------------------------------------------
    key = AESGCM(b"\x00" * 32)
    nonce = b"\x01" * 12
    payload = b"x" * 1024
    results.append(bench("AES-256-GCM encrypt 1 KiB", lambda: key.encrypt(nonce, payload, b"aad")))

    # -- Password hashing, the dominant per-login cost ------------------------
    results.append(bench("Argon2id (t=2, m=19MiB, p=1)", lambda: security.hash_password("a-long-enough-password"), rounds=10))

    width = max(len(row["label"]) for row in results)
    print(f"{'operation'.ljust(width)}   median      min     n")
    print("-" * (width + 26))
    for row in results:
        if row["median_ms"] is None:
            print(row["label"])
            continue
        print(
            f"{row['label'].ljust(width)}   "
            f"{row['median_ms']:7.3f}ms {row['min_ms']:7.3f}ms {row['rounds']:5d}"
        )

    # Key and ciphertext sizes matter as much as speed for a protocol that puts them on
    # the wire: ML-KEM-768 keys are what make a handshake 2 KB rather than 64 bytes.
    print()
    print(f"ML-KEM-768 encapsulation key : {pqc.EK_BYTES} bytes")
    print(f"ML-KEM-768 ciphertext        : {pqc.CT_BYTES} bytes")
    print(f"X25519 public key            : 32 bytes")
    print(f"Ed25519 signature            : 64 bytes")
    if pqsign.available():
        print(f"ML-DSA-65 public key         : {len(pq_pub)} bytes")
        print(f"ML-DSA-65 signature          : {len(pq_sig)} bytes")


if __name__ == "__main__":
    main()
