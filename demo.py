"""
demo.py - Type any message, see it encrypted step by step, then decrypted.

Run:   python demo.py                 (asks you to type a message, repeats until you type q)
       python demo.py "my message"    (one message from the command line)
In Colab use:  %run demo.py
"""
import sys
from cipher import (clean, pad, key_to_matrix, hill_encrypt, hill_decrypt,
                    vigenere_encrypt, vigenere_decrypt, HILL_KEY, VIG_KEY)


def show(message):
    plain = clean(message)
    if not plain:
        print("Please enter at least one letter (A-Z).\n")
        return

    M = key_to_matrix(HILL_KEY)
    padded = pad(plain)

    # ---- Encryption ----
    stage1 = hill_encrypt(plain, M)             # Hill
    cipher = vigenere_encrypt(stage1, VIG_KEY)  # Vigenere

    # ---- Decryption (reverse order) ----
    undo2 = vigenere_decrypt(cipher, VIG_KEY)   # undo Vigenere
    recovered = hill_decrypt(undo2, M)          # undo Hill
    final = recovered[:len(plain)]              # remove padding X

    print("\n" + "=" * 62)
    print("Keys   : Hill =", HILL_KEY, "| Vigenere =", VIG_KEY)
    print("=" * 62)
    print("ENCRYPTION")
    print("  Your message (A-Z only) :", plain)
    print("  After padding with X    :", padded)
    print("  Step 1 - after Hill     :", stage1)
    print("  Step 2 - after Vigenere :", cipher, " <-- CIPHERTEXT")
    print("-" * 62)
    print("DECRYPTION")
    print("  Step 1 - undo Vigenere  :", undo2)
    print("  Step 2 - undo Hill      :", recovered)
    print("  Remove padding          :", final)
    print("-" * 62)
    print("Decrypted matches original:", final == plain)
    print("=" * 62 + "\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        show(" ".join(sys.argv[1:]))
    else:
        print("Hill + Vigenere cipher demo (type q to quit)")
        while True:
            try:
                msg = input("Enter plaintext: ")
            except EOFError:
                break
            if msg.strip().lower() == "q":
                break
            show(msg)
