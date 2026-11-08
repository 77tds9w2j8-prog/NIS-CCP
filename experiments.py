"""
experiments.py  -  Runs all experiments and saves CSV files
  results_known_plaintext.csv  : success rate/time of known-plaintext attack vs ciphertext length
  results_known_amount.csv     : success rate vs amount of known plaintext
  results_frequency.csv        : frequency analysis on Hill+Vigenere vs Vigenere-only
  results_efficiency.csv       : encrypt/decrypt time, our cipher vs Shift cipher
"""
import csv
import random
import time

from cipher import (clean, encrypt, decrypt, shift_encrypt, shift_decrypt,
                    vigenere_encrypt, key_to_matrix, is_invertible, MOD)
from attack import (known_plaintext_attack, decrypt_with_recovered,
                    frequency_attack, letter_accuracy, index_of_coincidence)

random.seed(2026)           # reproducible results
TRIALS = 20
LENGTHS = [100, 500, 1000, 5000, 10000]

TEXT = clean(open("sample_text.txt", encoding="utf-8", errors="ignore").read())
if len(TEXT) < 20000:
    raise SystemExit("sample_text.txt needs at least 20,000 letters of English text.")


def random_chunk(n):
    start = random.randint(0, len(TEXT) - n)
    return TEXT[start:start + n]


def random_hill_key():
    while True:
        k = "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(16))
        if is_invertible(key_to_matrix(k)):
            return k


def random_vig_key(n=12):
    return "".join(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(n))


def save_csv(name, header, rows):
    with open(name, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print("saved", name)


# ---------------------------------------------------------------------
# Experiment 1: known-plaintext attack vs ciphertext length (48 known letters)
# ---------------------------------------------------------------------
def exp_known_plaintext(known_len=64):
    rows = []
    print("\n[1] Known-plaintext attack (known =", known_len, "letters)")
    for n in LENGTHS:
        ok, times = 0, []
        for _ in range(TRIALS):
            pt = random_chunk(n)
            hk, vk = random_hill_key(), random_vig_key()
            ct = encrypt(pt, hk, vk)
            t0 = time.perf_counter()
            res = known_plaintext_attack(pt[:known_len], ct)
            if res:
                rec = decrypt_with_recovered(ct, *res)
                if rec[:n] == pt:
                    ok += 1
            times.append(time.perf_counter() - t0)
        rate = 100 * ok / TRIALS
        avg_ms = 1000 * sum(times) / TRIALS
        rows.append([n, known_len, TRIALS, rate, round(avg_ms, 3)])
        print(f"  length {n:>6}: success {rate:5.1f}%   avg attack time {avg_ms:8.3f} ms")
    save_csv("results_known_plaintext.csv",
             ["ciphertext_length", "known_letters", "trials", "success_rate_pct", "avg_time_ms"], rows)


# ---------------------------------------------------------------------
# Experiment 2: success vs amount of known plaintext (ciphertext length 1000)
# ---------------------------------------------------------------------
def exp_known_amount(trials=50):
    rows = []
    print("\n[2] Success vs amount of known plaintext (length 1000,", trials, "trials)")
    for known in [16, 24, 28, 32, 40, 48, 64, 96]:
        ok = 0
        for _ in range(trials):
            pt = random_chunk(1000)
            hk, vk = random_hill_key(), random_vig_key()
            ct = encrypt(pt, hk, vk)
            res = known_plaintext_attack(pt[:known], ct)
            if res and decrypt_with_recovered(ct, *res)[:1000] == pt:
                ok += 1
        rate = 100 * ok / trials
        rows.append([known, trials, rate])
        print(f"  known {known:>3} letters: success {rate:5.1f}%")
    save_csv("results_known_amount.csv", ["known_letters", "trials", "success_rate_pct"], rows)


# ---------------------------------------------------------------------
# Experiment 3: frequency analysis
# ---------------------------------------------------------------------
def exp_frequency():
    rows = []
    print("\n[3] Frequency analysis")
    for n in LENGTHS:
        stats = {"hill+vigenere": [0, 0.0, 0.0, 0.0], "vigenere only": [0, 0.0, 0.0, 0.0]}
        for _ in range(TRIALS):
            pt = random_chunk(n)
            hk, vk = random_hill_key(), random_vig_key()
            targets = {"hill+vigenere": encrypt(pt, hk, vk),
                       "vigenere only": vigenere_encrypt(pt, vk)}
            for name, ct in targets.items():
                t0 = time.perf_counter()
                _, cand = frequency_attack(ct)
                dt = time.perf_counter() - t0
                acc = letter_accuracy(cand, pt)
                s = stats[name]
                s[0] += (cand[:n] == pt)
                s[1] += acc
                s[2] += dt
                s[3] += index_of_coincidence(ct)
        for name, s in stats.items():
            rows.append([name, n, TRIALS, 100 * s[0] / TRIALS, round(100 * s[1] / TRIALS, 2),
                         round(1000 * s[2] / TRIALS, 3), round(s[3] / TRIALS, 4)])
            print(f"  {name:<14} length {n:>6}: full success {100*s[0]/TRIALS:5.1f}%  "
                  f"letter accuracy {100*s[1]/TRIALS:5.1f}%  time {1000*s[2]/TRIALS:8.2f} ms  "
                  f"IC {s[3]/TRIALS:.4f}")
    save_csv("results_frequency.csv",
             ["cipher", "ciphertext_length", "trials", "full_success_pct",
              "avg_letter_accuracy_pct", "avg_time_ms", "avg_IC"], rows)


# ---------------------------------------------------------------------
# Experiment 4: efficiency vs Shift cipher
# ---------------------------------------------------------------------
def timeit(fn, *args, repeats=5):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn(*args)
        best = min(best, time.perf_counter() - t0)
    return best * 1000   # ms


def exp_efficiency():
    rows = []
    print("\n[4] Efficiency (best of 5 runs, ms)")
    for n in [1000, 10000, 100000, 1000000]:
        pt = (TEXT * (n // len(TEXT) + 1))[:n]
        ct = encrypt(pt)
        s_ct = shift_encrypt(pt)
        enc = timeit(encrypt, pt)
        dec = timeit(decrypt, ct)
        s_enc = timeit(shift_encrypt, pt)
        s_dec = timeit(shift_decrypt, s_ct)
        rows.append([n, round(enc, 3), round(dec, 3), round(s_enc, 3), round(s_dec, 3),
                     round(enc / s_enc, 2)])
        print(f"  n={n:>8}: ours enc {enc:9.3f}  dec {dec:9.3f} | shift enc {s_enc:8.3f}  "
              f"dec {s_dec:8.3f} | slowdown x{enc/s_enc:.1f}")
    save_csv("results_efficiency.csv",
             ["length", "ours_encrypt_ms", "ours_decrypt_ms", "shift_encrypt_ms",
              "shift_decrypt_ms", "encrypt_slowdown_x"], rows)


if __name__ == "__main__":
    exp_known_plaintext()
    exp_known_amount()
    exp_frequency()
    exp_efficiency()
    print("\nAll experiments done.")
