package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;

/**
 * Runs the relay protocol for one client connection.
 *
 * A session starts unregistered. The client sends its identity and public
 * keys, then signs a fresh challenge to prove possession of its signing key;
 * the relay then issues, stores and returns a signed credential. A registered
 * connection can request other users' credentials and submit protected
 * messages, which the relay forwards to online recipients without decrypting
 * them. PING is answered with PONG at any time.
 *
 * Each connection gets its own RelaySession object, so the session's state
 * lives in fields and each frame type has its own handler method.
 */
public final class RelaySession {
    // Generate unpredictable challenges.
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Where the session is in the protocol. Each frame type is accepted
     * only in the states listed in its handler.
     */
    private enum State {
        // Connected; nothing proved yet.
        NEW,
        // Registration request received; waiting for its proof.
        REGISTER_PENDING,
        // The client proved its identity; it may discover and send.
        AUTHENTICATED
    }

    private final Socket conn;
    private final PrivateKey relaySigningKey;
    private final ClientDirectory directory;

    // All responses and forwarded messages share this synchronized writer.
    private ClientConnection clientConnection;

    private State state = State.NEW;

    // False once the session should end after the current frame.
    private boolean open = true;

    // The registration in progress and its original bytes.
    private RegisterRequest pendingRegistration;
    private byte[] pendingRegistrationPayload;

    // The challenge in progress, timed with a monotonic clock.
    private byte[] pendingChallenge;
    private long pendingChallengeIssuedAtNanos;

    // The identity this connection proved; null until authenticated.
    private String identity;

    private RelaySession(Socket conn, PrivateKey relaySigningKey,
                         ClientDirectory directory) {
        this.conn = conn;
        this.relaySigningKey = relaySigningKey;
        this.directory = directory;
    }

    /**
     * Processes frames from one client until the connection ends.
     *
     * Reads use the protocol read timeout until the client authenticates;
     * the timeout is then removed so the client can wait for messages. A
     * protocol violation ends the session with an exception. When the
     * session ends, an authenticated client is marked offline but its
     * credential stays stored.
     *
     * @param conn the connected client socket
     * @param relaySigningKey the relay's Ed25519 key used to sign credentials
     * @param directory the shared directory of credentials and online clients
     * @throws IOException if reading or writing fails, a read times out,
     *                     or the client violates the protocol
     */
    public static void handle(Socket conn, PrivateKey relaySigningKey,
                              ClientDirectory directory) throws IOException {
        new RelaySession(conn, relaySigningKey, directory).run();
    }

    /**
     * Reads frames and dispatches each one to its handler.
     */
    private void run() throws IOException {
        conn.setSoTimeout(ProtocolConfig.READ_TIMEOUT_MILLIS);

        try (
                DataInputStream in = new DataInputStream(conn.getInputStream());
                DataOutputStream out = new DataOutputStream(conn.getOutputStream())
        ) {
            clientConnection = new ClientConnection(conn, out);

            while (open) {
                Frame request = FrameCodec.read(in);

                // Handle each frame according to its protocol type.
                switch (request.type()) {
                    case PING -> handlePing(request);
                    case REGISTER_REQUEST -> handleRegisterRequest(request);
                    case REGISTER_PROOF -> handleRegisterProof(request);
                    case DISCOVER_REQUEST -> handleDiscover(request);
                    case SEND_MESSAGE -> handleSend(request);
                    default -> throw new IOException(
                            "Unexpected message type: " + request.type());
                }
            }
        } catch (EOFException e) {
            // The incoming stream ended. Finish this session.
        } finally {
            // Only report offline if this connection was still the online one.
            if (identity != null && directory.markOffline(identity, clientConnection)) {
                System.out.println("[*] Client offline: " + identity);
            }
        }
    }

    /**
     * Answers an empty PING with an empty PONG, in any state.
     */
    private void handlePing(Frame request) throws IOException {
        if (request.payload().length != 0) {
            throw new IOException("Expected an empty PING frame");
        }

        clientConnection.send(new Frame(MessageType.PONG, new byte[0]));
    }

    /**
     * Starts a registration: validates the request and sends a challenge.
     */
    private void handleRegisterRequest(Frame request) throws IOException {
        requireState(State.NEW, "Registration not allowed now");

        // Keep the original bytes and validate their contents.
        pendingRegistrationPayload = request.payload();
        pendingRegistration = RegistrationCodec.decodeRequest(pendingRegistrationPayload);

        sendChallenge(MessageType.REGISTER_CHALLENGE);
        state = State.REGISTER_PENDING;

        System.out.println("[*] Challenge for "
                + pendingRegistration.identity() + " = "
                + HexFormat.of().formatHex(pendingChallenge));
    }

    /**
     * Verifies the registration proof, then issues and stores the credential.
     */
    private void handleRegisterProof(Frame request) throws IOException {
        requireState(State.REGISTER_PENDING, "No registration challenge pending");

        // Reconstruct the exact bytes the client must have signed.
        byte[] proofData = RegistrationCodec.buildProofData(
                pendingRegistrationPayload, consumeChallenge());

        try {
            // The proof payload contains the client's Ed25519 signature.
            if (!Signatures.verify(proofData, request.payload(),
                    pendingRegistration.signingPublicKey())) {
                throw new IOException("Invalid registration proof");
            }
        } catch (GeneralSecurityException e) {
            // Treat malformed signatures or verification failures as session errors.
            throw new IOException("Could not verify registration proof", e);
        }

        RegisterRequest verifiedRegistration = pendingRegistration;
        pendingRegistration = null;
        pendingRegistrationPayload = null;

        System.out.println("[*] Registration proof verified for "
                + verifiedRegistration.identity());

        // Issue a credential only after the client's proof has been verified.
        byte[] credentialPayload;
        try {
            credentialPayload = CredentialCodec.issue(
                    verifiedRegistration, relaySigningKey);
        } catch (GeneralSecurityException e) {
            throw new IOException("Could not sign registration credential", e);
        }

        // Reserve the identity before returning a successful registration.
        if (!directory.register(verifiedRegistration.identity(), credentialPayload)) {
            clientConnection.send(new Frame(MessageType.ERROR,
                    "Identity already registered".getBytes(StandardCharsets.UTF_8)));
            open = false;
            return;
        }

        System.out.println("[*] Stored credential for "
                + verifiedRegistration.identity());

        authenticate(verifiedRegistration.identity(),
                new Frame(MessageType.REGISTER_SUCCESS, credentialPayload));

        System.out.println("[*] Issued credential for "
                + verifiedRegistration.identity());
    }

    /**
     * Returns the stored credential for the requested identity.
     */
    private void handleDiscover(Frame request) throws IOException {
        requireState(State.AUTHENTICATED, "Authenticate before requesting discovery");

        String targetIdentity = DiscoveryCodec.decodeRequest(request.payload());

        // Retrieve the original credential bytes stored during registration.
        byte[] targetCredential = directory.find(targetIdentity);

        if (targetCredential == null) {
            clientConnection.send(new Frame(MessageType.ERROR,
                    "Identity not found".getBytes(StandardCharsets.UTF_8)));
        } else {
            clientConnection.send(new Frame(
                    MessageType.DISCOVER_RESPONSE, targetCredential));

            System.out.println("[*] Returned credential for "
                    + targetIdentity + " to " + identity);
        }
    }

    /**
     * Forwards a protected message to its recipient if they are online.
     */
    private void handleSend(Frame request) throws IOException {
        requireState(State.AUTHENTICATED, "Authenticate before sending messages");

        // Read routing metadata, the recipient independently authenticates it.
        MessageCodec.Header header = MessageCodec.readHeader(request.payload());

        // Bind the claimed sender to the identity proved on this connection.
        if (!identity.equals(header.sender())) {
            throw new IOException("Message sender does not match this connection");
        }

        ClientConnection recipient = directory.findOnline(header.recipient());

        if (recipient == null) {
            clientConnection.send(new Frame(MessageType.ERROR,
                    "Recipient is offline".getBytes(StandardCharsets.UTF_8)));
            return;
        }

        try {
            // Forward the original payload without decrypting or re-encoding it.
            recipient.send(new Frame(MessageType.DELIVER_MESSAGE, request.payload()));

            System.out.println("[*] Forwarded message "
                    + header.messageId() + " from " + header.sender()
                    + " to " + header.recipient());
        } catch (IOException e) {
            directory.markOffline(header.recipient(), recipient);

            clientConnection.send(new Frame(MessageType.ERROR,
                    "Could not forward message".getBytes(StandardCharsets.UTF_8)));
        }
    }

    /**
     * Marks this connection as the identity's online connection and
     * sends the success frame.
     */
    private void authenticate(String provedIdentity, Frame success)
            throws IOException {
        identity = provedIdentity;
        state = State.AUTHENTICATED;

        // Publish the connection while holding its writer lock.
        // Forwarding threads must wait until the success frame has been sent.
        synchronized (clientConnection) {
            directory.markOnline(identity, clientConnection);
            clientConnection.send(success);
        }

        // Authenticated clients may remain idle while waiting for messages.
        conn.setSoTimeout(0);
    }

    /**
     * Generates a fresh challenge, remembers it and sends it.
     */
    private void sendChallenge(MessageType type) throws IOException {
        pendingChallenge = new byte[ProtocolConfig.CHALLENGE_BYTES];
        RANDOM.nextBytes(pendingChallenge);
        pendingChallengeIssuedAtNanos = System.nanoTime();

        clientConnection.send(new Frame(type, pendingChallenge));
    }

    /**
     * Returns the pending challenge once, rejecting it if it has expired.
     */
    private byte[] consumeChallenge() throws IOException {
        byte[] challenge = pendingChallenge;

        // Consume the challenge before verification, so it can never be reused.
        pendingChallenge = null;

        if (challenge == null) {
            throw new IOException("No challenge pending");
        }

        // Reject an old challenge even if other frames kept the connection active.
        long ageNanos = System.nanoTime() - pendingChallengeIssuedAtNanos;
        if (ageNanos >= TimeUnit.MILLISECONDS.toNanos(
                ProtocolConfig.CHALLENGE_TIMEOUT_MILLIS)) {
            throw new IOException("Challenge expired");
        }

        return challenge;
    }

    /**
     * Ends the session if a frame arrives in the wrong state.
     */
    private void requireState(State expected, String message) throws IOException {
        if (state != expected) {
            throw new IOException(message);
        }
    }
}
