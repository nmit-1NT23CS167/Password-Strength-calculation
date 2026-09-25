# Password Strength Checker
 
A small, dependency-free Python project that scores password strength using
composition rules (length, character variety, common patterns) combined
with an entropy-based crack-time estimate.

## Requirements
 
Python 3.9+. No third-party packages — everything uses the standard library
(`re`, `math`, `dataclasses`, `getpass`).
 
## How to run it
 
**Interactive (input hidden, like a real password prompt):**
```
python3 password_strength.py
```
 
## How scoring works
 
1. **Entropy estimate** — `length × log2(character_pool_size)`, where the
   pool size grows with the character classes used (lowercase, uppercase,
   digits, symbols). This gives a rough baseline score from 0–4.
2. **Pattern penalties** — the entropy math alone can't tell that `"aaaa1111"`
   is a bad password, so the score is reduced for:
   - Membership in a small built-in common-password list
   - Sequential runs (`abcd`, `4321`)
   - Keyboard-adjacent runs (`qwerty`, `asdf`)
   - A character repeated 3+ times in a row
3. **Crack-time estimate** — converts entropy bits into a rough offline
   guessing-time estimate, assuming ~10 billion guesses/sec (a plausible
   rate for an attacker who has stolen a weakly-hashed password database
   and is guessing offline with GPUs). This is illustrative, not a precise
   forecast — real crack time depends heavily on the hashing algorithm used
   to store the password (bcrypt/scrypt/argon2 vs. unsalted MD5, for
   example).
   
## Limitations & how this would differ in production
 
- The built-in common-password list has few entries for demo purposes.
- This tool only *scores* a password; it doesn't store, hash, or transmit
 it anywhere. A real signup flow still needs to hash passwords with
  bcrypt/scrypt/argon2 before storing them — never store or log plaintext
  passwords, including in analytics or error logs.
- Entropy-from-character-pool is a simplification. It assumes each
  character is chosen independently and randomly from its pool
 
