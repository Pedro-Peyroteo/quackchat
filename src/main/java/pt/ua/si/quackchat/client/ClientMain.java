package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.crypto.KeyEnvelopes;
import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.*;

import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;

public class ClientMain {
    // Password source when no interactive terminal is available (decision D4).
    private static final String PASSWORD_VARIABLE = "QUACKCHAT_CLIENT_PASSWORD";

    /**
     * Starts as a registered identity and optionally sends one protected message.
     *
     * The client reads the relay's public key from keys/relay.cer and asks
     * for the identity's password. If clients/&lt;identity&gt;/identity.bin
     * exists, it loads and checks that file, then logs in by signing a fresh
     * relay challenge. Otherwise it generates new Ed25519 and RSA key pairs,
     * registers, and saves them to that file. With a contact, it then
     * discovers and verifies that contact's credential and sends one
     * encrypted, signed message. It stays connected and displays verified
     * incoming messages until stopped.
     *
     * A wrong password, a modified identity file, a rejected login or a
     * network failure ends the client with a one-line error and exit code 1.
     *
     * @param args {@code [host] [port] [identity] [contact] [message]};
     *             defaults are localhost, 5000 and "alice"
     * @throws IllegalArgumentException if too many arguments are supplied
     *                                  or the port is invalid
     */
    public static void main(String[] args) {
        try {
            run(args);
        } catch (IOException | GeneralSecurityException | IllegalStateException e) {
            // Show expected failures (wrong password, rejected login, ...)
            // as one line instead of a stack trace.
            System.err.println("[!] " + e.getMessage());
            System.exit(1);
        }
    }

    /**
     * Runs the client; see {@link #main(String[])}.
     */
    private static void run(String[] args) throws IOException, GeneralSecurityException {
        // Accept an optional host, port, identity, contact and message.
        if (args.length > 5) {
            throw new IllegalArgumentException(
                    "Usage: ClientMain [host] [port] [identity] [contact] [message]");
        }

        String host = args.length >= 1
                ? args[0] : ProtocolConfig.DEFAULT_RELAY_HOST;
        int port = args.length >= 2
                ? parsePort(args[1]) : ProtocolConfig.DEFAULT_RELAY_PORT;
        String identity = args.length >= 3 ? args[2] : "alice";
        String contact = args.length >= 4 ? args[3] : null;

        // Preserve the existing greeting when no message argument is supplied.
        String messageText = args.length == 5
                ? args[4]
                : "Hello, " + contact + "!";

        // Validate the names before asking for a password or connecting.
        if (contact != null) {
            DiscoveryCodec.encodeRequest(contact);
        }
        Path identityFile = IdentityStore.pathFor(identity);

        PublicKey trustedRelayKey = loadTrustedRelayKey();

        boolean returning = Files.exists(identityFile);
        char[] password = readPassword(identity, !returning);

        try {
            // Load and check the file before any network traffic, so a wrong
            // password or a modified file fails locally.
            ClientIdentity me = returning
                    ? IdentityStore.load(identityFile, identity, password, trustedRelayKey)
                    : null;

            if (returning) {
                System.out.println("[*] Loaded identity file " + identityFile);
            }

            try (Socket conn = new Socket()) {
                conn.connect(
                        new InetSocketAddress(host, port),
                        ProtocolConfig.CONNECT_TIMEOUT_MILLIS
                );
                conn.setSoTimeout(ProtocolConfig.READ_TIMEOUT_MILLIS);

                try (
                        // Wrap the connection's incoming and outgoing bytes.
                        DataInputStream in = new DataInputStream(conn.getInputStream());
                        DataOutputStream out = new DataOutputStream(conn.getOutputStream())
                ) {
                    System.out.println("[*] Connected to relay");

                    if (returning) {
                        login(in, out, me);
                    } else {
                        me = register(in, out, identity, trustedRelayKey);

                        // Save only after the relay's credential has been verified (D6).
                        IdentityStore.save(identityFile, me, password);
                        System.out.println("[*] Saved identity file " + identityFile);
                    }

                    // Keep the authenticated connection open while waiting for messages.
                    conn.setSoTimeout(0);

                    ClientInbox inbox = new ClientInbox(
                            identity, me.encryptionKeys().getPrivate(), trustedRelayKey);

                    if (contact != null) {
                        sendMessage(in, out, inbox, me, contact, messageText, trustedRelayKey);
                    }

                    // Both senders and recipients remain available for incoming messages.
                    System.out.println("[*] Waiting for messages; press Ctrl+C to stop");
                    inbox.listen(in);
                }
            }
        } finally {
            // The password is needed until the identity file has been saved.
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Reads the relay public key from the X.509 certificate exported by keytool.
     *
     * Trust comes from provisioning this file through a trusted setup channel.
     */
    private static PublicKey loadTrustedRelayKey()
            throws IOException, GeneralSecurityException {
        try (InputStream certificateInput =
                     Files.newInputStream(Path.of("keys/relay.cer"))) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate =
                    (X509Certificate) factory.generateCertificate(certificateInput);

            certificate.checkValidity();
            return certificate.getPublicKey();
        }
    }

    /**
     * Reads the identity password from the terminal, or from
     * QUACKCHAT_CLIENT_PASSWORD when no terminal is available (decision D4).
     *
     * @param identity the identity, shown in the prompt
     * @param confirm whether to ask twice, for a new identity file
     * @return the password; the caller must wipe it
     */
    private static char[] readPassword(String identity, boolean confirm) {
        Console console = System.console();

        // IntelliJ and redirected runs have no real terminal to read from.
        if (console == null || !console.isTerminal()) {
            String configured = System.getenv(PASSWORD_VARIABLE);
            if (configured == null || configured.isEmpty()) {
                throw new IllegalStateException(
                        "No terminal available; set " + PASSWORD_VARIABLE);
            }
            return configured.toCharArray();
        }

        String prompt = confirm
                ? "New password for " + identity + ": "
                : "Password for " + identity + ": ";
        char[] password = console.readPassword(prompt);

        if (password == null || password.length == 0) {
            throw new IllegalStateException("A password is required");
        }

        if (confirm) {
            char[] repeated = console.readPassword("Repeat the password: ");
            boolean same = Arrays.equals(password, repeated);
            if (repeated != null) {
                Arrays.fill(repeated, '\0');
            }

            if (!same) {
                Arrays.fill(password, '\0');
                throw new IllegalStateException("Passwords do not match");
            }
        }

        return password;
    }

    /**
     * Registers a new identity: generates key pairs, proves possession of
     * the signing key and verifies the credential the relay returns.
     *
     * @return the new identity with its verified credential
     */
    private static ClientIdentity register(DataInputStream in, DataOutputStream out,
                                           String identity, PublicKey trustedRelayKey)
            throws IOException, GeneralSecurityException {
        // Generate the client's signing and encryption key pairs.
        KeyPair signingKeys = Signatures.generateKeyPair();
        KeyPair encryptionKeys = KeyEnvelopes.generateKeyPair();

        // Build and encode the request using the identity and public keys.
        RegisterRequest registration = new RegisterRequest(
                identity, signingKeys.getPublic(), encryptionKeys.getPublic());
        byte[] registrationPayload = RegistrationCodec.encodeRequest(registration);

        System.out.println("[*] Prepared registration for " + identity
                + " (" + registrationPayload.length + " bytes)");

        FrameCodec.write(out, new Frame(MessageType.REGISTER_REQUEST, registrationPayload));
        out.flush();
        System.out.println("[*] Sent registration request");

        // Wait for the relay's registration challenge.
        Frame response = FrameCodec.read(in);

        // Validate the response type and the fixed challenge length.
        if (response.type() != MessageType.REGISTER_CHALLENGE
                || response.payload().length != ProtocolConfig.CHALLENGE_BYTES) {
            throw new IOException("Expected a registration challenge");
        }

        byte[] challenge = response.payload();
        System.out.println("[*] Received challenge = "
                + HexFormat.of().formatHex(challenge));

        // Build the same signature input that the relay will reconstruct,
        // and prove ownership of the submitted signing key.
        byte[] proofData = RegistrationCodec.buildProofData(registrationPayload, challenge);
        byte[] proofSignature = Signatures.sign(proofData, signingKeys.getPrivate());

        FrameCodec.write(out, new Frame(MessageType.REGISTER_PROOF, proofSignature));
        out.flush();
        System.out.println("[*] Sent registration proof ("
                + proofSignature.length + " bytes)");

        // Wait for the signed credential returned after proof verification.
        Frame result = FrameCodec.read(in);

        if (result.type() == MessageType.ERROR) {
            throw new IOException("Registration rejected: "
                    + new String(result.payload(), StandardCharsets.UTF_8));
        }

        if (result.type() != MessageType.REGISTER_SUCCESS) {
            throw new IOException("Expected registration success");
        }

        // Verify the credential with the previously trusted relay key.
        byte[] credentialPayload = result.payload();
        Credential credential = CredentialCodec.verify(credentialPayload, trustedRelayKey);

        // Ensure the relay certified the identity and keys this client submitted.
        byte[] certifiedRegistration =
                RegistrationCodec.encodeRequest(credential.registration());

        if (!Arrays.equals(certifiedRegistration, registrationPayload)) {
            throw new IOException("Credential does not match our registration");
        }

        System.out.println("[*] Verified relay credential for "
                + credential.registration().identity());
        System.out.println("[*] Credential issued at " + credential.issuedAt());

        return new ClientIdentity(identity, credentialPayload, signingKeys, encryptionKeys);
    }

    /**
     * Resumes a registered identity by signing a fresh relay challenge
     * with the stored signing key (decision D7).
     */
    private static void login(DataInputStream in, DataOutputStream out, ClientIdentity me)
            throws IOException, GeneralSecurityException {
        // The request names the identity only; the relay uses the key it stored.
        FrameCodec.write(out, new Frame(
                MessageType.LOGIN_REQUEST, LoginCodec.encodeRequest(me.identity())));
        out.flush();
        System.out.println("[*] Sent login request for " + me.identity());

        Frame response = FrameCodec.read(in);

        // An unknown identity is reported clearly; never re-register (D9).
        if (response.type() == MessageType.ERROR) {
            throw new IOException("Login rejected: "
                    + new String(response.payload(), StandardCharsets.UTF_8));
        }

        if (response.type() != MessageType.LOGIN_CHALLENGE
                || response.payload().length != ProtocolConfig.CHALLENGE_BYTES) {
            throw new IOException("Expected a login challenge");
        }

        byte[] proofData = LoginCodec.buildProofData(me.identity(), response.payload());
        byte[] proofSignature = Signatures.sign(proofData, me.signingKeys().getPrivate());

        FrameCodec.write(out, new Frame(MessageType.LOGIN_PROOF, proofSignature));
        out.flush();

        Frame result = FrameCodec.read(in);

        if (result.type() == MessageType.ERROR) {
            throw new IOException("Login rejected: "
                    + new String(result.payload(), StandardCharsets.UTF_8));
        }

        if (result.type() != MessageType.LOGIN_SUCCESS || result.payload().length != 0) {
            throw new IOException("Expected login success");
        }

        System.out.println("[*] Logged in as " + me.identity());
    }

    /**
     * Discovers the contact, verifies their credential and sends one
     * encrypted, signed message.
     */
    private static void sendMessage(DataInputStream in, DataOutputStream out,
                                    ClientInbox inbox, ClientIdentity me,
                                    String contact, String messageText,
                                    PublicKey trustedRelayKey)
            throws IOException, GeneralSecurityException {
        // Ask for the contact's registered credential.
        FrameCodec.write(out, new Frame(
                MessageType.DISCOVER_REQUEST, DiscoveryCodec.encodeRequest(contact)));
        out.flush();

        // Process incoming deliveries if they arrive before the discovery response.
        Frame discoveryResult = inbox.readResponse(in);

        if (discoveryResult.type() == MessageType.ERROR) {
            throw new IOException("Discovery failed: "
                    + new String(discoveryResult.payload(), StandardCharsets.UTF_8));
        }

        if (discoveryResult.type() != MessageType.DISCOVER_RESPONSE) {
            throw new IOException("Expected a discovery response");
        }

        // Verify the returned credential using the previously trusted relay key.
        Credential contactCredential = CredentialCodec.verify(
                discoveryResult.payload(), trustedRelayKey);

        // A valid credential must also belong to the identity we requested.
        if (!contact.equals(contactCredential.registration().identity())) {
            throw new IOException("Discovery returned a different identity");
        }

        System.out.println("[*] Discovered and verified "
                + contactCredential.registration().identity());
        System.out.println("[*] Contact credential issued at "
                + contactCredential.issuedAt());

        // Encrypt for the recipient and sign with this client's signing key.
        byte[] messagePayload = MessageCodec.protect(
                me.identity(),
                contact,
                messageText.getBytes(StandardCharsets.UTF_8),
                me.credential(),
                me.signingKeys().getPrivate(),
                contactCredential.registration().encryptionPublicKey()
        );

        MessageCodec.Header messageHeader = MessageCodec.readHeader(messagePayload);
        System.out.println("[*] Prepared protected message "
                + messageHeader.messageId() + " for " + contact
                + " (" + messagePayload.length + " bytes)");

        // Submit the protected envelope to the relay for forwarding.
        FrameCodec.write(out, new Frame(MessageType.SEND_MESSAGE, messagePayload));
        out.flush();

        System.out.println("[*] Sent protected message to relay");
    }

    /**
     * Parses and validates a port number.
     *
     * The port must be a numeric value in the valid TCP/UDP port
     * range from 1 to 65535.
     *
     * @param value the port number as a string
     * @return the validated port number
     * @throws IllegalArgumentException if the supplied value is not
     *                                  numeric or falls outside the
     *                                  valid port range
     */
    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65_535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Port must be a number between 1 and 65535", e);
        }
    }
}
