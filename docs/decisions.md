# Design decisions

Working log of QuackChat design decisions, newest at the bottom.
The architecture document condenses these; this file keeps the alternatives and reasons.

---

## D1 — One Maven project with a shared package

- **Date:** 2026-11-16
- **Decision:** Client and relay live in one Maven project. Byte formats and crypto helpers sit in `shared.protocol` and `shared.crypto`; the `client` and `relay` packages do not import each other.
- **Alternatives:** Separate projects or Maven modules (shared, client, relay) producing two artifacts.
- **Why:** Both sides must agree on the exact bytes that are signed and encrypted, so they share the codecs. Security must not depend on hiding source code (Kerckhoffs's principle). The assignment requires both components' source in one submission anyway.
- **Consequences:** Separation happens at runtime instead: `relay.p12` exists only on the relay, client private keys only on the client, and each party uses its own data directory.

## D2 — Client identity saved to an encrypted file

- **Date:** 2026-11-24
- **Decision:** The client saves its identity, the relay-signed credential and both private keys (Ed25519 and RSA, PKCS#8 encoding) in one encrypted file.
- **Alternatives:** Private keys only, with the credential returned by the relay at login. A PKCS#12 keystore.
- **Why:** The JDK has no API to derive an Ed25519 public key from the private key, and the credential already contains both public keys. Every outgoing envelope includes the sender's own credential. On load, the client can check that its keys match its credential without contacting the relay. PKCS#12 requires a certificate for every private key, which the JDK cannot create without `keytool`.
- **Consequences:** The stored credential can differ from the relay's copy if the relay ever re-issues credentials; there is no re-issue or revocation yet.

## D3 — Identity file format

- **Date:** 2026-11-24
- **Decision:** Binary file:

  | Offset | Size | Field |
    |---|---|---|
  | 0 | 4 | magic `QCID` |
  | 4 | 1 | version `0x01` |
  | 5 | 4 | PBKDF2 iterations (Int32) |
  | 9 | 16 | salt |
  | 25 | 12 | GCM nonce |
  | 37 | rest | AES-GCM ciphertext and 16-byte tag |

  The 37-byte header is the GCM associated data. The key is AES-256 from PBKDF2-HMAC-SHA256 (password, salt, iterations). The plaintext is `F(identity) || F(credential) || F(Ed25519 PKCS#8) || F(RSA PKCS#8)`. A new salt and nonce are used on every save.
- **Alternatives:** Fixed parameters with only salt and nonce stored. A text format (key=value with Base64). PKCS#12 (see D2).
- **Why:** Storing the parameters allows raising the iteration count later without breaking old files. The same pattern will be used for the relay store (module C), so code and documentation are shared. 600,000 iterations follows the current OWASP recommendation for PBKDF2-HMAC-SHA256.
- **Consequences:** Salt and iterations already feed the key, so changing them makes GCM fail without help from the associated data; the associated data matters for the magic, version and future cleartext fields. On load, the iteration count must be within fixed minimum and maximum bounds (a huge value would hang the client). Saves always use the program's constant, never the value read from the file. Writes go to a temporary file followed by an atomic move. A wrong password and a damaged file give the same error.

## D4 — Source of the client password

- **Date:** 2026-11-24
- **Decision:** `System.console().readPassword()`; if no console is available (e.g. IntelliJ), the `QUACKCHAT_CLIENT_PASSWORD` environment variable.
- **Alternatives:** A command-line argument.
- **Why:** Matches how the relay reads its keystore password. Arguments end up in shell history and in process listings.
- **Consequences:** An environment variable is visible to other processes run by the same user; acceptable for development, noted as a limitation.

## D5 — One data directory per client

- **Date:** 2026-11-24
- **Decision:** `clients/<identity>/identity.bin`, ignored by Git through the anchored rule `/clients/`.
- **Alternatives:** A single file per client with no directory.
- **Why:** More per-client files are planned: seen message IDs (replay protection), accepted group member-list versions, and possibly pinned contact credentials. Separate directories also stop parties from sharing files during local demos.
- **Consequences:** The relay will get its own anchored data directory (piece 5).

## D6 — Client startup behaviour

- **Date:** 2026-11-24
- **Decision:** If the identity file exists, load it, run the local checks (relay signature on the credential, identity equals the argument, private keys match the credential's public keys), then log in (D7). If not, register, and save the file only after a verified `REGISTER_SUCCESS`.
- **Alternatives:** Save the keys before registering.
- **Why:** A failed registration must not leave behind a key file for an identity that does not exist on the relay.
- **Consequences:** A missing or damaged file means the identity can no longer be used; there is no recovery path (see D8 consequences and the threat report).

## D7 — Dedicated login protocol

- **Date:** 2026-11-24
- **Decision:** New message types `LOGIN_REQUEST`, `LOGIN_CHALLENGE`, `LOGIN_PROOF`, `LOGIN_SUCCESS`. The request carries only the identity. The relay sends a fresh 32-byte challenge with the same lifetime as registration. The client signs `F("QuackChat:login-proof:v1") || F(identity) || F(challenge)` with its Ed25519 key. The relay verifies the signature with the key stored at registration, never with a key from the request.
- **Alternatives:** Treat a repeated registration with the same keys as a login. A logout that frees the name.
- **Why:** Matches section 4.3 of the architecture document. A separate context string means a registration proof cannot be used as a login proof, or the reverse. A logout that frees the name would let anyone register the identity with their own keys and receive its messages, breaking authenticity.
- **Consequences:** Without TLS, an on-path attacker can inject frames into a connection after login. Fetch and acknowledge requests for stored messages will therefore be signed (piece 6).

## D8 — Second login for the same identity

- **Date:** 2026-11-24
- **Decision:** Newest wins. Only after the new connection's proof is verified, the relay replaces the online entry, sends the old connection an error ("Session replaced by a new login") and closes it. A login request alone never changes the online map.
- **Alternatives:** Reject the second login while the first connection is open.
- **Why:** A crashed client leaves a half-open connection; rejecting would lock the owner out until it times out. A successful login requires the private key, so a second login is either the owner or a key thief. A key thief can log in whenever the owner is offline under either policy; with newest-wins, the owner sees the takeover when online.
- **Consequences:** Threat table row: key theft is detectable but not preventable without revocation. Login proves possession of the Ed25519 key only, not the RSA key.

## D9 — Relay restart forgets identities (temporary)

- **Date:** 2026-11-24
- **Decision:** Until the relay directory is persisted (piece 5), a relay restart forgets all registrations. A client with an identity file then fails to log in and shows a clear error. It does not register again automatically.
- **Alternatives:** Automatically register again with the same keys.
- **Why:** Automatic re-registration would bring back the same-key path rejected in D7.
- **Consequences:** During development, delete `clients/*/` after restarting the relay.

## D10 — Password-based encryption parameters

- **Date:** 2026-11-24
- **Decision:** PBKDF2-HMAC-SHA256 with a 16-byte random salt and 600,000 iterations, deriving an AES-256 key used with AES-GCM (12-byte nonce, 16-byte tag). Iterations accepted on load: 600,000 to 6,000,000. Shared by the client identity file and, later, the relay store (`PasswordEncryption`).
- **Alternatives:** AES-128 (as for message keys). Fewer iterations. A memory-hard function such as scrypt or Argon2 (not in the JDK).
- **Why:**
  - **Salt:** NIST SP 800-132 requires at least 128 random bits. With 16 bytes, two files sharing a salt is negligible, so precomputed tables are useless and every file must be attacked on its own.
  - **Iterations:** OWASP recommends 600,000 for PBKDF2-HMAC-SHA256, so each password guess costs an attacker 600,000 HMAC computations. Measured: 224 ms per derivation on Windows 11, JDK 25.0.5.1 (`PasswordEncryptionCheck`, 2026-11-24). This was the first derivation in the process, so it includes JVM and crypto-provider start-up and slightly overstates the normal cost. The figure is what a user pays per unlock, not what an attacker pays: dedicated hardware such as GPUs computes PBKDF2-HMAC-SHA256 much faster, which is why the count is set from a published recommendation rather than from this measurement.
  - **Bounds:** the minimum equals the default because no weaker file exists; accepting fewer would only help an attacker who edits a file. The maximum stops a tampered file from stalling the program.
  - **AES-256:** the password, not the key size, limits security, so AES-128 would be defensible too. AES-256 costs nothing here and matches the relay store design. Message keys stay at 128 bits because each protects a single message.
- **Consequences:** Security still depends on password strength; PBKDF2 only slows guessing and is not memory-hard. Java cannot guarantee secrets are wiped from memory, so wiping is best-effort. Deriving 64 bytes with PBKDF2-HMAC-SHA256 runs the full iteration count twice while an attacker needs only the first 32 bytes; to be reconsidered for the relay store.

## D11 — Identity file is never overwritten

- **Date:** 2026-11-25
- **Decision:** `IdentityStore.save` refuses to write if the file already exists. Writes go to `identity.bin.tmp` and are moved into place in one step. Identities are validated against `[A-Za-z0-9_-]+` before being used in a path.
- **Alternatives:** Overwrite on save. Build the path from the raw identity.
- **Why:** The file holds the only copy of the private keys; losing it locks the identity out for good (D6). The temporary file means a crash cannot leave a half-written file. The character check stops an identity such as `../keys` from writing outside `clients/` (path traversal).
- **Consequences:** Threat-table rows: path traversal through the identity name (mitigated), stolen identity file (offline password guessing, slowed by PBKDF2, D10). Changing the password would need a separate, explicit operation; not planned.

---

## Open questions

- **Group sends and the admin:** section 4.4 requires the admin to confirm the member-list version before every send, which blocks the group while the admin is offline. To be reconsidered before implementing module B.
- **Replay protection across restarts:** seen message IDs are kept only in memory; to be persisted in the client directory (piece 8).