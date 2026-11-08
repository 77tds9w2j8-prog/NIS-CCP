# NIS CCP - Hill + Vigenere Custom Cipher

Network and Information Security (CT-486) - Complex Computing Problem

## Files
- `cipher.py`      - Hill (4x4) + Vigenere (12 letters) encryption/decryption, Shift cipher for comparison
- `attack.py`      - Known-plaintext attack and frequency analysis attack
- `experiments.py` - Runs all experiments, writes `results_*.csv`
- `sample_text.txt`- English text used as test plaintext

## How to run
    python cipher.py        # demo + round-trip tests
    python attack.py        # attack demo
    python experiments.py   # all experiments (~1 min), saves CSV files

Requires Python 3.8+ (no external libraries).

## Keys
- Hill key: `HILLCIPHERSECRET` (16 letters -> 4x4 matrix)
- Vigenere key: `SECURITYLABS` (12 letters)
