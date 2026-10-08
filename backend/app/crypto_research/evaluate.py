# AEGIS-X128 Research Evaluation -- EXPERIMENTAL, NOT FOR PRODUCTION
from __future__ import annotations
import os, time, statistics, tracemalloc, math, sys
sys.path.insert(0, r"c:\Users\rishi\Documents\trae_projects\aegis\backend")
from app.crypto_research.cipher import AegisX128
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def test_correctness(trials=100):
    passed = 0
    for i in range(trials):
        key = os.urandom(32)
        pt = os.urandom((i % 255) + 1)
        aad = os.urandom(8) if i % 2 == 0 else None
        c = AegisX128(key)
        ct, tag = c.encrypt(pt, aad)
        rec = c.decrypt(ct, tag, aad)
        if rec == pt: passed += 1
    return passed, trials

def test_tamper(trials=100):
    detected = 0
    for _ in range(trials):
        key = os.urandom(32)
        c = AegisX128(key)
        ct, tag = c.encrypt(b"hello")
        bad = bytes(b ^ 0xFF for b in tag)
        try:
            c.decrypt(ct, bad)
        except Exception:
            detected += 1
    return detected, trials

def test_entropy(data_size=65536):
    key = os.urandom(32)
    c = AegisX128(key)
    ct, _ = c.encrypt(bytes(data_size))
    freq = [0]*256
    for b in ct: freq[b] += 1
    n = len(ct)
    entropy = -sum((f/n)*math.log2(f/n) for f in freq if f > 0)
    return round(entropy, 4), n

def bench_aegis(data_size=65536, rounds=5):
    key = os.urandom(32)
    c = AegisX128(key)
    times = []
    tracemalloc.start()
    for _ in range(rounds):
        t0 = time.perf_counter()
        c.encrypt(bytes(data_size))
        times.append(time.perf_counter() - t0)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    avg = statistics.mean(times)
    return round((data_size/1024/1024)/avg, 2), round(avg*1000, 2), round(peak/1024, 1)

def bench_aes(data_size=65536, rounds=5):
    key = os.urandom(32)
    nonce = os.urandom(12)
    gcm = AESGCM(key)
    times = []
    tracemalloc.start()
    for _ in range(rounds):
        t0 = time.perf_counter()
        gcm.encrypt(nonce, bytes(data_size), None)
        times.append(time.perf_counter() - t0)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    avg = statistics.mean(times)
    return round((data_size/1024/1024)/avg, 2), round(avg*1000, 2), round(peak/1024, 1)

def run():
    print("=" * 60)
    print("AEGIS-X128 Research Evaluation")
    print("EXPERIMENTAL - NOT FOR PRODUCTION")
    print("AES-256-GCM remains the production standard")
    print("=" * 60)
    print()
    passed, total = test_correctness()
    status = "PASS" if passed == total else "FAIL"
    print(f"1. Correctness:   {passed}/{total} {status}")
    det, tot = test_tamper()
    status = "PASS" if det == tot else "FAIL"
    print(f"2. Tamper detect: {det}/{tot} {status}")
    ent, n = test_entropy()
    status = "PASS" if ent >= 7.5 else "LOW"
    print(f"3. Entropy:       {ent} bits/byte ({n} bytes) {status}")
    print()
    mb_aegis, ms_aegis, mem_aegis = bench_aegis()
    mb_aes, ms_aes, mem_aes = bench_aes()
    print("4. Performance (64KB, 5 rounds):")
    print(f"   AegisX128   : {mb_aegis:6.1f} MB/s  avg={ms_aegis}ms  mem={mem_aegis}KB")
    print(f"   AES-256-GCM : {mb_aes:6.1f} MB/s  avg={ms_aes}ms  mem={mem_aes}KB")
    print()
    print("5. Design limitations (research prototype only):")
    print("   - CTR mode does not provide ciphertext diffusion")
    print("   - CBC-MAC is weaker than GCM GHASH for large data")
    print("   - Key schedule uses PBKDF2 (slow by design)")
    print("   - Algorithm not formally analyzed or peer-reviewed")
    print("   - AES-256-GCM is the ONLY production encryption in Aegis")

if __name__ == "__main__":
    run()