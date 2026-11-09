package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.crypto.KeyEnvelopes;
import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.HexFormat;

public class ClientMain {

    /**
     * Starts the client application and performs a single PING/PONG
     * exchange with a relay server.
     *
     * The first optional argument specifies the relay host and the
     * second optional argument specifies the relay port.
     *
     * @param args command-line arguments in the form
     *             {@code [host] [port]}
     * @throws IOException if a network error occurs, a timeout is reached,
     *                     or the relay returns an invalid response
     * @throws IllegalArgumentException if too many arguments are supplied
     *                                  or the specified port is invalid
     *
     * @throws GeneralSecurityException if client key generation fails
     */
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        // Accept and optional host, port and client identity.
        if (args.length > 3) {
            throw new IllegalArgumentException("Usage: ClientMain [host] [port] [identity]");
        }

        String host = args.length >= 1 ? args[0] : ProtocolConfig.DEFAULT_RELAY_HOST;
        int port = args.length >= 2 ? parsePort(args[1]) : ProtocolConfig.DEFAULT_RELAY_PORT;
        String identity = args.length == 3 ? args[2] : "alice";

        // Generate the client's signing and encryption key pairs.
        KeyPair signingKeys = Signatures.generateKeyPair();
        KeyPair encryptionKeys = KeyEnvelopes.generateKeyPair();

        // Build the request using the identity and public keys.
        RegisterRequest registration = new RegisterRequest(identity, signingKeys.getPublic(), encryptionKeys.getPublic());

        // Encode the request into the bytes the frame will carry.
        byte[] registrationPayload = RegistrationCodec.encodeRequest(registration);

        System.out.println("[*] Prepared registration for " + identity + "(" + registrationPayload.length + "bytes)");

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

                // Send the identity and public keys prepared before connecting.
                FrameCodec.write(out, new Frame(MessageType.REGISTER_REQUEST, registrationPayload));
                out.flush();
                System.out.println("[*] Sent registration request");

                // Wait for the relay's registration challenge.
                Frame response = FrameCodec.read(in);

                // Validate the response type and the fixed challenge length.
                if (response.type() != MessageType.REGISTER_CHALLENGE
                        || response.payload().length
                        != ProtocolConfig.REGISTRATION_CHALLENGE_BYTES) {
                    throw new IOException("Expected a registration challenge");
                }

                // Keep the received bytes for the signed proof that will be constructed next.
                byte[] challenge = response.payload();
                System.out.println("[*] Received challenge = "
                        + HexFormat.of().formatHex(challenge));

                // Build the same signature input that the relay will reconstruct.
                byte[] proofData = RegistrationCodec.buildProofData(registrationPayload, challenge);

                // Prove ownership of the private key matching the submitted signing public key.
                byte[] proofSignature = Signatures.sign(proofData, signingKeys.getPrivate());

                // Send the signature as the registration proof payload.
                FrameCodec.write(out, new Frame(MessageType.REGISTER_PROOF, proofSignature));
                out.flush();

                System.out.println("[*] Sent registration proof ("
                        + proofSignature.length + ") bytes");
            }
        }
        // The socket and its streams are closed.
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
