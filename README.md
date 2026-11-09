# QuackChat — Phase 1

Java TCP messaging prototype implementing registration, discovery and
protected delivery of a message between two online clients.

---

## Requirements

- JDK 25, including `java` and `keytool`.
- Maven.
- Run the commands below from the project root.
- The examples use PowerShell.

---

## Build

```powershell
mvn compile
```

Compiled application classes are written to `target/classes`.

---

## Provision the relay identity

Perform this setup once for a new local environment.
Reuse existing key files for subsequent runs.

```powershell
New-Item -ItemType Directory -Path keys -Force
```

```powershell
keytool -genkeypair -alias relay -keyalg Ed25519 -storetype PKCS12 -keystore keys/relay.p12 -dname "CN=QuackChat Relay" -validity 365
```

Choose a keystore password when prompted.

Export the relay's public certificate:

```powershell
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
available to the Java process:

```powershell
$relayPassword = Read-Host "Relay keystore password" -AsSecureString
$env:QUACKCHAT_RELAY_KEYSTORE_PASSWORD = [System.Net.NetworkCredential]::new("", $relayPassword).Password
```

Start the relay:

```powershell
java -cp target/classes pt.ua.si.quackchat.relay.RelayMain
```

The default port is 5000. An optional first argument overrides it.

When using IntelliJ, set `QUACKCHAT_RELAY_KEYSTORE_PASSWORD` in the RelayMain
run configuration and use the project root as its working directory.

---

## Run the two-client demo

Leave the relay running.

In a second terminal, register Bob and leave him connected:

```powershell
java -cp target/classes pt.ua.si.quackchat.client.ClientMain localhost 5000 bob
```

Wait for:

```text
[*] Waiting for messages; press Ctrl+C to stop
```

In a third terminal, register Alice, discover Bob and send a message:

```powershell
java -cp target/classes pt.ua.si.quackchat.client.ClientMain localhost 5000 alice bob "This is our Phase 1 demo!"
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

Without a contact, the client registers and listens.
With a contact, it discovers that identity, sends one message and then listens.
Without explicit message text, it sends `Hello, <contact>!`.

Use Ctrl+C to stop clients. Restart the relay before repeating the demo with
the same identities, because registrations remain in memory until it stops.

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

Not yet exercised:

- Modified-message and replay rejection.
- Expired-challenge rejection.

---

## Current limitations

- Client keys exist only in process memory and are regenerated at startup.
- The directory is in memory and is cleared when the relay restarts.
- Registered identities cannot currently reconnect during the same relay run.
- One outgoing message is supplied at startup; interactive messaging is pending.
- Offline message storage and retrieval are not implemented.
- Accepted message IDs are remembered only for the client process lifetime.
- Credentials include issuance time; expiry and revocation are not implemented.
- Registration challenges have a 30-second acceptance limit.
- Registration reads have a five-second timeout; registered clients can wait
  indefinitely for messages.
- Usernames identify registered keys, not independently verified real-world people.