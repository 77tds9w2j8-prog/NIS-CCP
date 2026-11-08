"""
attack.py  -  Attacks on the Hill + Vigenere cipher

1) Known-plaintext attack (breaks the full cipher)
2) Frequency analysis attack (breaks Vigenere alone, fails on Hill + Vigenere)

Attacker knowledge (Kerckhoffs' principle): the attacker knows the algorithm,
the Hill block size (4) and the Vigenere key length (12). Only the keys are secret.
"""
from itertools import combinations
from math import gcd
from cipher import (clean, to_nums, to_text, mat_mul, mat_inv_mod, hill_encrypt,
                    vigenere_decrypt, hill_decrypt, det, BLOCK, MOD)

ENGLISH_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
                0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
                6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]   # percent


# =====================================================================
# 1) KNOWN-PLAINTEXT ATTACK
# =====================================================================
# Ciphertext block i  =  H * P_i  +  K_(i mod 3)       (K = Vigenere key chunk)
# For two blocks with the same key chunk:  C_i - C_j = H * (P_i - P_j)
# The Vigenere key cancels out, leaving a pure Hill problem we can solve.
def vec_sub(a, b):
    return [(x - y) % MOD for x, y in zip(a, b)]


def known_plaintext_attack(known_pt, ciphertext, vig_len=12):
    """
    known_pt   : known plaintext, which is the FIRST letters of the message
    ciphertext : the full ciphertext (or at least the first len(known_pt) letters)
    Returns (hill_matrix, vigenere_key) or None if the known text is not enough.
    """
    known_pt = clean(known_pt)
    n_blocks = min(len(known_pt), len(ciphertext)) // BLOCK
    phases = vig_len // BLOCK                      # key chunks per cycle (3)
    P = [to_nums(known_pt[i * BLOCK:(i + 1) * BLOCK]) for i in range(n_blocks)]
    C = [to_nums(ciphertext[i * BLOCK:(i + 1) * BLOCK]) for i in range(n_blocks)]

    # Step 1: difference pairs between blocks that share the same key chunk
    base = {}          # first block index seen for each phase
    diffs = []         # (delta_P, delta_C)
    for i in range(n_blocks):
        ph = i % phases
        if ph not in base:
            base[ph] = i
        else:
            diffs.append((vec_sub(P[i], P[base[ph]]), vec_sub(C[i], C[base[ph]])))
    if len(base) < phases or len(diffs) < BLOCK:
        return None

    # Step 2: pick 4 differences whose plaintext matrix is invertible mod 26
    diffs = diffs[:14]
    H = None
    for combo in combinations(range(len(diffs)), BLOCK):
        DP = [[diffs[c][0][r] for c in combo] for r in range(BLOCK)]   # columns = vectors
        if gcd(det(DP) % MOD, MOD) != 1:
            continue
        DC = [[diffs[c][1][r] for c in combo] for r in range(BLOCK)]
        H = mat_mul(DC, mat_inv_mod(DP))                                # H = DC * DP^-1
        break
    if H is None:
        return None

    # Step 3: recover the Vigenere key chunks  K = C - H*P
    key_nums = []
    for ph in range(phases):
        i = base[ph]
        hp = [sum(H[r][k] * P[i][k] for k in range(BLOCK)) % MOD for r in range(BLOCK)]
        key_nums.extend(vec_sub(C[i], hp))
    return H, to_text(key_nums)


def decrypt_with_recovered(ciphertext, H, vig_key):
    return hill_decrypt(vigenere_decrypt(ciphertext, vig_key), H)


# =====================================================================
# 2) FREQUENCY ANALYSIS ATTACK (Vigenere-style)
# =====================================================================
def index_of_coincidence(text):
    n = len(text)
    if n < 2:
        return 0.0
    counts = [text.count(chr(65 + i)) for i in range(26)]
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def chi_squared(text):
    n = len(text)
    if n == 0:
        return float("inf")
    counts = [text.count(chr(65 + i)) for i in range(26)]
    return sum((counts[i] - n * ENGLISH_FREQ[i] / 100) ** 2 / (n * ENGLISH_FREQ[i] / 100)
               for i in range(26))


def guess_key_length(ciphertext, max_len=20):
    """Average IC of the columns for each key length; pick the smallest good one."""
    scores = {}
    for L in range(1, max_len + 1):
        cols = [ciphertext[i::L] for i in range(L)]
        scores[L] = sum(index_of_coincidence(c) for c in cols) / L
    best = max(scores.values())
    for L in range(1, max_len + 1):
        if scores[L] >= 0.9 * best:
            return L
    return 1


def frequency_attack(ciphertext, max_len=20):
    """Guess key length with IC, then solve each column as a Caesar shift with chi-squared.
    Returns (guessed_key, candidate_plaintext)."""
    L = guess_key_length(ciphertext, max_len)
    key = ""
    for i in range(L):
        col = ciphertext[i::L]
        best_shift, best_score = 0, float("inf")
        for s in range(26):
            dec = "".join(chr((ord(ch) - 65 - s) % 26 + 65) for ch in col)
            score = chi_squared(dec)
            if score < best_score:
                best_shift, best_score = s, score
        key += chr(65 + best_shift)
    return key, vigenere_decrypt(ciphertext, key)


def letter_accuracy(candidate, truth):
    """Fraction of positions where the candidate matches the true plaintext."""
    n = min(len(candidate), len(truth))
    if n == 0:
        return 0.0
    return sum(1 for a, b in zip(candidate, truth) if a == b) / n


# =====================================================================
# Demo
# =====================================================================
if __name__ == "__main__":
    import os
    from cipher import encrypt, decrypt, HILL_KEY, VIG_KEY

    path = "sample_text.txt"
    text = clean(open(path, encoding="utf-8", errors="ignore").read())[:2000]
    ct = encrypt(text)
    print("Ciphertext IC:", round(index_of_coincidence(ct), 4),
          "(English ~0.0667, random ~0.0385)")

    print("\n--- Known-plaintext attack (attacker knows first 48 letters) ---")
    res = known_plaintext_attack(text[:48], ct)
    if res:
        H, vk = res
        print("Recovered Vigenere key:", vk, "| real key:", VIG_KEY)
        rec = decrypt_with_recovered(ct, H, vk)
        print("Full plaintext recovered:", rec[:len(text)] == text)
    else:
        print("Not enough known plaintext")

    print("\n--- Frequency analysis on Hill + Vigenere ---")
    k, cand = frequency_attack(ct)
    print("Guessed key:", k, "| letter accuracy:", round(letter_accuracy(cand, text), 3))
