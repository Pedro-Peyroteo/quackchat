package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;

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
    public static void handle(Socket conn) throws IOException {
        conn.setSoTimeout(ProtocolConfig.READ_TIMEOUT_MILLIS);

        try (
                DataInputStream in = new DataInputStream(conn.getInputStream());
                DataOutputStream out = new DataOutputStream(conn.getOutputStream())
        ) {
            // Keep the pending registration and challenge with this connection.
            RegisterRequest pendingRegistration = null;
            byte[] pendingRegistrationPayload = null;
            byte[] pendingChallenge = null;

            // Keep the registration whose signing-key ownership has been verified.
            RegisterRequest verifiedRegistration = null;

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

                        FrameCodec.write(out, new Frame(MessageType.PONG, new byte[0]));
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

                        // Return the challenge bytes to the client.
                        FrameCodec.write(out, new Frame(MessageType.REGISTER_CHALLENGE, pendingChallenge));

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

                    }

                    default -> throw new IOException("Unexpected message type: " + request.type());
                }

                // Send the response before waiting for the next frame.
                out.flush();
            }
        } catch (EOFException e) {
            // The incoming stream ended. Finish this session.
        }
    }
}
