"""
cipher.py  -  Custom two-stage classical cipher
Stage 1: Hill cipher (4x4 key matrix, block size 4)
Stage 2: Vigenere cipher (12-letter key)

Encrypt : plaintext -> Hill -> Vigenere -> ciphertext
Decrypt : ciphertext -> inverse Vigenere -> inverse Hill -> plaintext
"""
import string
from math import gcd

ALPHABET = string.ascii_uppercase
MOD = 26
BLOCK = 4

# ---- The keys -------------------------------------------------------------
HILL_KEY = "HILLCIPHERSECRET" # 16 letters -> 4x4 matrix (row by row, A=0 ... Z=25)
VIG_KEY = "SECURITYLABS"        # 12 letters (a multiple of the Hill block size)


# ---- Helpers --------------------------------------------------------------
def clean(text):
    """Uppercase and keep only A-Z."""
    return "".join(ch for ch in text.upper() if ch in ALPHABET)


def pad(text, filler="X"):
    """Pad with X so the length is a multiple of the block size."""
    r = len(text) % BLOCK
    return text if r == 0 else text + filler * (BLOCK - r)


def to_nums(text):
    return [ord(ch) - 65 for ch in text]


def to_text(nums):
    return "".join(chr(n % MOD + 65) for n in nums)


# ---- Matrix math mod 26 ---------------------------------------------------
def key_to_matrix(key):
    key = clean(key)
    if len(key) != BLOCK * BLOCK:
        raise ValueError("Hill key must have exactly 16 letters")
    nums = to_nums(key)
    return [nums[r * BLOCK:(r + 1) * BLOCK] for r in range(BLOCK)]


def minor(M, i, j):
    return [row[:j] + row[j + 1:] for k, row in enumerate(M) if k != i]


def det(M):
    """Determinant by cofactor expansion (fine for 4x4)."""
    if len(M) == 1:
        return M[0][0]
    return sum(((-1) ** j) * M[0][j] * det(minor(M, 0, j)) for j in range(len(M)))


def is_invertible(M):
    return gcd(det(M) % MOD, MOD) == 1


def mat_inv_mod(M):
    """Inverse of a square matrix mod 26 using the adjugate."""
    d = det(M) % MOD
    if gcd(d, MOD) != 1:
        raise ValueError("Matrix is not invertible mod 26")
    d_inv = pow(d, -1, MOD)
    n = len(M)
    inv = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            cof = ((-1) ** (i + j)) * det(minor(M, i, j))
            inv[j][i] = (cof * d_inv) % MOD   # transpose of cofactors = adjugate
    return inv


def mat_mul(A, B):
    return [[sum(A[i][k] * B[k][j] for k in range(len(B))) % MOD
             for j in range(len(B[0]))] for i in range(len(A))]


def mat_vec(M, v):
    return [sum(M[i][k] * v[k] for k in range(len(v))) % MOD for i in range(len(M))]


# ---- Stage 1: Hill --------------------------------------------------------
def hill_encrypt(text, M):
    nums = to_nums(pad(text))
    out = []
    for i in range(0, len(nums), BLOCK):
        out.extend(mat_vec(M, nums[i:i + BLOCK]))
    return to_text(out)


def hill_decrypt(text, M):
    return hill_encrypt(text, mat_inv_mod(M))   # same operation with inverse matrix


# ---- Stage 2: Vigenere ----------------------------------------------------
def vigenere_encrypt(text, key):
    k = to_nums(clean(key))
    return "".join(chr((ord(ch) - 65 + k[i % len(k)]) % MOD + 65)
                   for i, ch in enumerate(text))


def vigenere_decrypt(text, key):
    k = to_nums(clean(key))
    return "".join(chr((ord(ch) - 65 - k[i % len(k)]) % MOD + 65)
                   for i, ch in enumerate(text))


# ---- Combined cipher ------------------------------------------------------
def encrypt(plaintext, hill_key=HILL_KEY, vig_key=VIG_KEY):
    M = key_to_matrix(hill_key)
    if not is_invertible(M):
        raise ValueError("Hill key matrix is not invertible mod 26")
    if len(clean(vig_key)) < 10:
        raise ValueError("Vigenere key must have at least 10 letters")
    stage1 = hill_encrypt(clean(plaintext), M)
    return vigenere_encrypt(stage1, vig_key)


def decrypt(ciphertext, hill_key=HILL_KEY, vig_key=VIG_KEY):
    """Returns the plaintext (may end with padding X letters)."""
    M = key_to_matrix(hill_key)
    stage1 = vigenere_decrypt(clean(ciphertext), vig_key)
    return hill_decrypt(stage1, M)


# ---- Single-stage Shift cipher (for efficiency comparison) ----------------
def shift_encrypt(text, shift=7):
    return "".join(chr((ord(ch) - 65 + shift) % MOD + 65) for ch in text)


def shift_decrypt(text, shift=7):
    return shift_encrypt(text, -shift)


# ---- Demo -----------------------------------------------------------------
if __name__ == "__main__":
    print("Hill matrix determinant mod 26:", det(key_to_matrix(HILL_KEY)) % MOD,
          "-> invertible:", is_invertible(key_to_matrix(HILL_KEY)))
    messages = [
        "Hello World",
        "Network and Information Security is a fun course",
        "A",
        "The quick brown fox jumps over the lazy dog " * 10,
    ]
    for msg in messages:
        ct = encrypt(msg)
        pt = decrypt(ct)
        ok = pt.startswith(clean(msg)) and set(pt[len(clean(msg)):]) <= {"X"}
        print("-" * 60)
        print("Plaintext :", clean(msg)[:60])
        print("Ciphertext:", ct[:60])
        print("Decrypted :", pt[:60])
        print("Round trip OK:", ok)
