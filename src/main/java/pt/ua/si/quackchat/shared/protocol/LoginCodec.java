package pt.ua.si.quackchat.shared.protocol;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Encodes login requests and the bytes signed as login proof (decision D7).
 *
 * LOGIN_REQUEST carries only the identity. The relay answers with a fresh
 * challenge and checks the client's signature against the signing key it
 * stored at registration, never against a key sent by the client.
 */
public final class LoginCodec {
    // Separates login proofs from registration proofs, credentials and messages.
    private static final byte[] PROOF_CONTEXT =
            "QuackChat:login-proof:v1".getBytes(StandardCharsets.UTF_8);

    private LoginCodec() {}

    /**
     * Encodes the identity the client wants to resume.
     *
     * @param identity the registered identity
     * @return the LOGIN_REQUEST payload
     * @throws IOException if the identity is invalid
     */
    public static byte[] encodeRequest(String identity) throws IOException {
        // Same identity rules and encoding as discovery.
        return DiscoveryCodec.encodeRequest(identity);
    }

    /**
     * Decodes a LOGIN_REQUEST payload.
     *
     * @param payload the received bytes
     * @return the validated identity
     * @throws IOException if the payload is not a valid identity
     */
    public static String decodeRequest(byte[] payload) throws IOException {
        return DiscoveryCodec.decodeRequest(payload);
    }

    /**
     * Builds the bytes signed for a login proof:
     * F("QuackChat:login-proof:v1") || F(identity) || F(challenge).
     *
     * @param identity the identity being resumed
     * @param challenge the relay's challenge for this login
     * @return the bytes covered by the login signature
     * @throws IOException if a field is invalid
     */
    public static byte[] buildProofData(String identity, byte[] challenge)
            throws IOException {
        if (challenge == null || challenge.length != ProtocolConfig.CHALLENGE_BYTES) {
            throw new IOException("Invalid login challenge length");
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            // Bind the signature to this operation and version.
            Fields.write(out, PROOF_CONTEXT, PROOF_CONTEXT.length);

            // Bind it to the identity being resumed...
            Fields.write(out, encodeRequest(identity),
                    RegistrationCodec.MAX_IDENTITY_BYTES);

            // ...and to this login attempt.
            Fields.write(out, challenge, ProtocolConfig.CHALLENGE_BYTES);
        }

        return buffer.toByteArray();
    }
}
