# QuackChat

Java TCP messaging prototype implementing registration, login with a stored
identity, discovery and protected delivery of a message between two online
clients. Phase 2 work in progress.

---

## Requirements

- JDK 25, including `java` and `keytool`.
- Maven.
- Run the commands below from the project root.
- Commands work in Bash and PowerShell unless a specific shell is shown.

---

## Build

**From the project's root:**

```sh
mvn compile
```

Compiled application classes are written to `target/classes`.

---

## Provision the relay identity

Perform this setup once for a new local environment.
Reuse existing key files for subsequent runs.

**Linux (Bash)**

```bash
mkdir -p keys
```

**Windows (PowerShell)**

```powershell
New-Item -ItemType Directory -Path keys -Force
```

Generate the relay key pair.

```sh
keytool -genkeypair -alias relay -keyalg Ed25519 -storetype PKCS12 -keystore keys/relay.p12 -dname "CN=QuackChat Relay" -validity 365
```

Choose a keystore password when prompted.

Export the relay's public certificate:

```sh
keytool -exportcert -alias relay -keystore keys/relay.p12 -file keys/relay.cer
```

- `relay.p12` contains the relay's private signing key and stays with the relay.
- `relay.cer` supplies the public key trusted by clients.
- Clients must obtain the genuine certificate through trusted provisioning.
- The `keys/` directory is excluded from Git.

For a local demo, relay and clients use the files in the same project directory.
For separate machines, provision only the public certificate to clients at
`keys/relay.cer`.

---

## Run the relay

In the relay terminal, read the password without displaying it and make it
available to the Java process.

**Linux (Bash)**

```bash
IFS= read -r -s -p 'Relay keystore password: ' QUACKCHAT_RELAY_KEYSTORE_PASSWORD
printf '\n'
export QUACKCHAT_RELAY_KEYSTORE_PASSWORD
```

**Windows (PowerShell)**

```powershell
$relayPassword = Read-Host "Relay keystore password" -AsSecureString
$env:QUACKCHAT_RELAY_KEYSTORE_PASSWORD = [System.Net.NetworkCredential]::new("", $relayPassword).Password
```

Start the relay.

```sh
java -cp target/classes pt.ua.si.quackchat.relay.RelayMain
```

The default port is 5000. An optional first argument overrides it.

When using IntelliJ, set `QUACKCHAT_RELAY_KEYSTORE_PASSWORD` in the RelayMain
run configuration and use the project root as its working directory.

---

## Client identities and passwords

Each client keeps its identity in `clients/<identity>/identity.bin`: the
relay-signed credential and both private keys, encrypted with a key derived
from the identity's password. The `clients/` directory is excluded from Git.

- First run for an identity: the client registers, then asks for a new
  password twice and saves the file.
- Later runs: the client asks for the password, loads and checks the file,
  then logs in instead of registering.

In a terminal, the client prompts for the password without displaying it.
Without a terminal (for example in IntelliJ), set the password in
`QUACKCHAT_CLIENT_PASSWORD` instead:

**Linux (Bash)**

```bash
IFS= read -r -s -p 'Client password: ' QUACKCHAT_CLIENT_PASSWORD
printf '\n'
export QUACKCHAT_CLIENT_PASSWORD
```

**Windows (PowerShell)**

```powershell
$clientPassword = Read-Host "Client password" -AsSecureString
$env:QUACKCHAT_CLIENT_PASSWORD = [System.Net.NetworkCredential]::new("", $clientPassword).Password
```

A lost password or identity file cannot be recovered; the identity can no
longer be used.

---

## Run the two-client demo

Leave the relay running.

In a second terminal, register Bob and leave him connected:

```sh
java -cp target/classes pt.ua.si.quackchat.client.ClientMain localhost 5000 bob
```

Wait for:

```text
[*] Waiting for messages; press Ctrl+C to stop
```

In a third terminal, register Alice, discover Bob and send a message:

```sh
java -cp target/classes pt.ua.si.quackchat.client.ClientMain localhost 5000 alice bob 'This is our Phase 1 demo!'
```

Bob should print:

```text
[*] Verified message <message UUID> from alice
alice: This is our Phase 1 demo!
```

The same UUID appears in Alice's preparation log and the relay's forwarding log.

Client arguments:

```text
ClientMain [host] [port] [identity] [contact] [message]
```

Without a contact, the client registers or logs in, then listens.
With a contact, it discovers that identity, sends one message and then listens.
Without explicit message text, it sends `Hello, <contact>!`.

Use Ctrl+C to stop clients.

### Reconnect with a stored identity

Stop Alice with Ctrl+C and run the same command again. Alice now loads
`clients/alice/identity.bin`, logs in and sends another message:

```text
[*] Loaded identity file clients/alice/identity.bin
[*] Sent login request for alice
[*] Logged in as alice
```

If an identity logs in again while its first client is still connected, the
newest login wins. The older client prints:

```text
[!] Relay error: Session replaced by a new login
```

### After restarting the relay

The relay keeps registrations in memory only, so after a restart a stored
identity is unknown and its login fails with `Login rejected: Unknown identity`.
Delete the identity directories before repeating the demo:

**Linux (Bash)**

```bash
rm -rf clients
```

**Windows (PowerShell)**

```powershell
Remove-Item -Recurse -Force clients
```

---

## Security flow

1. Each client generates Ed25519 signing keys and RSA-3072 encryption keys.
2. Registration submits the identity and both public keys.
3. The relay generates a random 32-byte challenge.
4. The client signs a purpose-specific encoding of the request and challenge.
5. The relay verifies the proof and returns a signed credential containing the
   identity, both public keys and issuance time.
6. Discovery returns the stored credential. The requester verifies its relay
   signature and checks the requested identity.
7. Each message uses a fresh AES-128 key and 12-byte AES-GCM nonce.
8. RSA-OAEP with SHA-256 and MGF1-SHA-256 protects the AES key for the recipient.
9. The message header is GCM associated data. An Ed25519 signature covers the
   complete envelope, including the sender's credential.
10. The recipient verifies the credential, sender, recipient and signature,
    unwraps the AES key, verifies the GCM tag, and displays the plaintext.
11. After registering, the client saves its credential and private keys in an
    identity file protected with AES-256-GCM, using a key derived from its
    password with PBKDF2-HMAC-SHA256 (600,000 iterations, random 16-byte salt).
12. On later runs, the client checks the file locally (GCM tag, relay
    signature on the credential, keys matching the credential), then sends a
    login request naming only its identity. The relay answers with a fresh
    32-byte challenge, and the client signs a login-specific encoding of its
    identity and the challenge. The relay verifies the signature with the
    signing key stored at registration.

The relay forwards the original protected payload and does not decrypt it.
Routing identities and other metadata remain visible.

---

## Verification performed

Manually observed:

- Two clients register and verify their credentials.
- Alice discovers and verifies Bob's credential.
- Bob verifies and decrypts a custom message forwarded through the relay.
- Duplicate identities are rejected.
- Unknown contacts are rejected.
- Offline recipients are rejected while their credentials remain discoverable.
- Abrupt disconnects are reported without the observed connection-reset
  stack traces during established sessions.

Phase 2 additions, observed in local runs:

- A returning client loads its identity file and logs in; messages still flow.
- A second login for a connected identity replaces the first; the first
  client is told why, and new messages reach the second.
- A wrong password fails locally, before connecting.
- After a relay restart, login fails with `Unknown identity`.

Runnable checks (after `mvn test-compile`; in PowerShell, quote the classpath
and use `;` as the separator):

```sh
java -cp target/classes:target/test-classes pt.ua.si.quackchat.shared.crypto.SignaturesCheck
java -cp target/classes:target/test-classes pt.ua.si.quackchat.shared.crypto.PasswordEncryptionCheck
java -cp target/classes:target/test-classes pt.ua.si.quackchat.client.IdentityStoreCheck
```

Not yet exercised:

- Modified-message and replay rejection.
- Expired-challenge rejection.

On Ubuntu under WSL, we verified the Bash steps for creating the key directory,
exporting the relay password, and quoting the demo message. The full build and
two-client demo on Linux with JDK 25 and Maven are pending verification.

---

## Current limitations

- The relay directory is in memory and is cleared when the relay restarts;
  stored client identities must then be deleted.
- One outgoing message is supplied at startup; interactive messaging is pending.
- Offline message storage and retrieval are not implemented.
- Accepted message IDs are remembered only for the client process lifetime.
- Credentials include issuance time; expiry and revocation are not implemented.
- Registration and login challenges have a 30-second acceptance limit.
- Reads have a five-second timeout until the client authenticates;
  authenticated clients can wait indefinitely for messages.
- Without TLS, an attacker on the network path could inject frames into a
  connection after login (to be addressed with signed requests for stored
  messages).
- Usernames identify registered keys, not independently verified real-world people.
