# Ferox
## File encryption program

> [!WARNING]
> This is for educational purposes only.
> I'm not responsible for any damage resulting from misuse of this program.

Ferox uses an Authenticated Encryption with Associated Data (AEAD) cipher, which resists nonce reuse and significantly improves security bounds, while eliminating the most catastrophic risks associated with nonce reuse in AES-GCM. For password hashing, Ferox employs **Argon2**, a modern, memory- and time-hard algorithm designed to securely store passwords. Argon2 protects against brute-force attacks by requiring configurable amounts of memory and computation, and the Argon2id variant used by Ferox provides a balance of resistance to GPU-based attacks and side-channel attacks, making password storage both safe and efficient.
