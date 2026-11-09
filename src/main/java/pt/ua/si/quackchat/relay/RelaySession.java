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
 * Handles a single relay protocol session with a connected client.
 *
 * A relay session consists of a simple request-response exchange:
 * the client sends an empty {@link MessageType#PING} frame and the
 * relay replies with an empty {@link MessageType#PONG} frame.
 *
 * This class is implemented as a utility class and cannot be
 * instantiated.
 */
public final class RelaySession {
    // Generate unpredictable registration challenges.
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Prevents instantiation of this utility class.
     */
    private RelaySession() {}

    /**
     * Processes a single client connection.
     *
     * The method configures the socket read timeout, reads a frame
     * from the client, validates that it is an empty
     * {@link MessageType#PING} frame, and responds with an empty
     * {@link MessageType#PONG} frame.
     *
     * If the received frame does not conform to the protocol,
     * an {@link IOException} is thrown and the session is terminated.
     *
     * @param conn the connected client socket
     * @throws IOException if an I/O error occurs while reading or writing
     *                     frames, if a timeout occurs, or if the received
     *                     frame is not a valid empty PING request
     */
    public static void handle(Socket conn, PrivateKey relaySigningKey, ClientDirectory directory)
            throws IOException {
        conn.setSoTimeout(ProtocolConfig.READ_TIMEOUT_MILLIS);

        // Keep enough state to remove the live connection when this session ends.
        ClientConnection clientConnection = null;
        String registeredIdentity = null;

        try (
                DataInputStream in = new DataInputStream(conn.getInputStream());
                DataOutputStream out = new DataOutputStream(conn.getOutputStream())
        ) {
            // All responses and forwarded messages share this synchronized writer.
            clientConnection = new ClientConnection(out);

            // Keep the pending registration and challenge with this connection.
            RegisterRequest pendingRegistration = null;
            byte[] pendingRegistrationPayload = null;
            byte[] pendingChallenge = null;

            // Keep the registration whose signing-key ownership has been verified.
            RegisterRequest verifiedRegistration = null;

            // Track challenge age using a monotonic clock.
            long pendingChallengeIssuedAtNanos = 0;

            while (true) {
                Frame request = FrameCodec.read(in);

                // Handle each frame according to its protocol type.
                // To add more types, add a case clause.
                switch (request.type()) {
                    case PING -> {
                        // A PING must have an empty payload.
                        if (request.payload().length != 0) {
                            throw new IOException("Expected an empty PING frame");
                        }

                        clientConnection.send(new Frame(MessageType.PONG, new byte[0]));
                    }

                    case REGISTER_REQUEST -> {
                        // Allow a registration request only before proof verification.
                        if (pendingRegistration != null || verifiedRegistration != null) {
                            throw new IOException("Registration already pending or verified");
                        }

                        // Keep the original bytes and validate their contents.
                        pendingRegistrationPayload = request.payload();
                        pendingRegistration = RegistrationCodec.decodeRequest(pendingRegistrationPayload);

                        // Generate a fresh challenge for this registration.
                        pendingChallenge = new byte[ProtocolConfig.REGISTRATION_CHALLENGE_BYTES];
                        RANDOM.nextBytes(pendingChallenge);

                        pendingChallengeIssuedAtNanos = System.nanoTime();

                        // Return the challenge bytes to the client.
                        clientConnection.send(new Frame(MessageType.REGISTER_CHALLENGE, pendingChallenge));

                        System.out.println("[*] Challenge for "
                                + pendingRegistration.identity() + " = "
                                + HexFormat.of().formatHex(pendingChallenge));
                    }

                    case REGISTER_PROOF -> {
                        // Accept proof only when this connection has a pending challenge.
                        if (pendingRegistration == null
                                || pendingRegistrationPayload == null
                                || pendingChallenge == null) {
                            throw new IOException("No registration challenge pending");
                        }

                        // Reject an old challenge even if other frames kept the connection active.
                        long challengeAgeNanos =
                                System.nanoTime() - pendingChallengeIssuedAtNanos;

                        if (challengeAgeNanos >= TimeUnit.MILLISECONDS.toNanos(
                                ProtocolConfig.REGISTRATION_CHALLENGE_TIMEOUT_MILLIS)) {
                            throw new IOException("Registration challenge expired");
                        }

                        // Reconstruct the exact bytes the client must have signed.
                        byte[] proofData = RegistrationCodec.buildProofData(pendingRegistrationPayload, pendingChallenge);

                        // Consume the challenge before attempting verification.
                        pendingChallenge = null;

                        try {
                            // The proof payload contains the client's Ed25519 signature.
                            boolean valid = Signatures.verify(
                                    proofData,
                                    request.payload(),
                                    pendingRegistration.signingPublicKey());

                            if (!valid) {
                                throw new IOException("Invalid registration proof");
                            }
                        } catch (GeneralSecurityException e) {
                            // Treat malformed signatures or verification failures as session errors.
                            throw new IOException("Could not verify registration proof", e);
                        }

                        // Preserve the verified registration for credential issuance.
                        verifiedRegistration = pendingRegistration;

                        // Release the pending request after successful verification.
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
                        if (!directory.register(
                                verifiedRegistration.identity(), credentialPayload)) {
                            clientConnection.send(new Frame(
                                    MessageType.ERROR,
                                    "Identity already registered".getBytes(StandardCharsets.UTF_8)));

                            return;
                        }

                        System.out.println("[*] Stored credential for "
                                + verifiedRegistration.identity());

                        registeredIdentity = verifiedRegistration.identity();

                        // Publish the connection while holding its writer lock.
                        // Forwarding threads must wait until REGISTER_SUCCESS has been sent.
                        synchronized (clientConnection) {
                            directory.markOnline(registeredIdentity, clientConnection);

                            clientConnection.send(new Frame(
                                    MessageType.REGISTER_SUCCESS, credentialPayload));
                        }

                        // Registered clients may remain idle while waiting for messages.
                        conn.setSoTimeout(0);

                        System.out.println("[*] Issued credential for "
                                + verifiedRegistration.identity());

                    }
                    case DISCOVER_REQUEST -> {
                        // Require this connection to complete registration before discovery.
                        if (verifiedRegistration == null) {
                            throw new IOException("Register before requesting discovery");
                        }

                        String targetIdentity =
                                DiscoveryCodec.decodeRequest(request.payload());

                        // Retrieve the original credential bytes stored during registration.
                        byte[] targetCredential = directory.find(targetIdentity);

                        if (targetCredential == null) {
                            clientConnection.send(new Frame(MessageType.ERROR,
                                    "Identity not found".getBytes(StandardCharsets.UTF_8)));
                        } else {
                            clientConnection.send(new Frame(MessageType.DISCOVER_RESPONSE, targetCredential));

                            System.out.println("[*] Returned credential for "
                                    + targetIdentity + " to " + verifiedRegistration.identity());
                        }
                    }
                    case SEND_MESSAGE -> {
                        if (registeredIdentity == null) {
                            throw new IOException("Register before sending messages");
                        }

                        // Read routing metadata, the recipient independently authenticates it.
                        MessageCodec.Header header = MessageCodec.readHeader(request.payload());

                        // Bind the claimed sender to the identity registered on this connection.
                        if (!registeredIdentity.equals(header.sender())) {
                            throw new IOException("Message sender does not match this connection");
                        }

                        ClientConnection recipient = directory.findOnline(header.recipient());

                        if (recipient == null) {
                            clientConnection.send(new Frame(
                                    MessageType.ERROR,
                                    "Recipient is offline".getBytes(StandardCharsets.UTF_8)));
                        } else {
                            try {
                                // Forward the original payload without decrypting or re-encoding it.
                                recipient.send(new Frame(
                                        MessageType.DELIVER_MESSAGE, request.payload()));

                                System.out.println("[*] Forwarded message "
                                        + header.messageId() + " from " + header.sender()
                                        + " to " + header.recipient());
                            } catch (IOException e) {
                                directory.markOffline(header.recipient(), recipient);

                                clientConnection.send(new Frame(
                                        MessageType.ERROR,
                                        "Could not forward message".getBytes(StandardCharsets.UTF_8)));
                            }
                        }
                    }
                    default -> throw new IOException("Unexpected message type: " + request.type());
                }
            }
        } catch (EOFException e) {
            // The incoming stream ended. Finish this session.
        } finally {
            if (registeredIdentity != null) {
                directory.markOffline(registeredIdentity, clientConnection);
                System.out.println("[*] Client offline: " + registeredIdentity);
            }
        }
    }
}
