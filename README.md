# Ferox

> [!WARNING]
> This is for educational purposes only.
> I'm not responsible for any damage resulting from misuse of this program.

Ferox is a file encryption program that derives encryption keys from user passwords using Argon2, a modern, memory- and time-hard password hashing algorithm. By using the Argon2id variant, Ferox ensures that keys are resistant to brute-force and GPU-based attacks, while remaining safe against side-channel attacks. The derived key is then used with an Authenticated Encryption with Associated Data (AEAD) cipher, which resists nonce reuse and significantly improves security bounds, eliminating the most catastrophic risks associated with nonce reuse in AES-GCM.
