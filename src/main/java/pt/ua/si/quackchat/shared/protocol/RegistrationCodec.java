package pt.ua.si.quackchat.shared.protocol;

import pt.ua.si.quackchat.shared.crypto.Signatures;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class RegistrationCodec {
    // Maximum encoded lengths accepted by the registration protocol.
    public static final int MAX_IDENTITY_BYTES = 64;
    private static final int MAX_PUBLIC_KEY_BYTES = 1_024;

    // Maximum encoded request size:
    //   Three int length prefixes: 3 * 4 = 12 bytes.
    //   Identity: up to 64 bytes.
    //   Two public-key fields: up to 2 * 1,024 bytes.
    //   Total: 12 + 64 + 2,048 = 2,124 bytes.
    // Actual requests may be smaller.
    static final int MAX_REQUEST_BYTES = 3 * Integer.BYTES + MAX_IDENTITY_BYTES + 2 * MAX_PUBLIC_KEY_BYTES;

    // Identify the protocol operation these signatures belong to.
    private static final byte[] PROOF_CONTEXT  = "QuackChat:registration-proof:v1".getBytes(StandardCharsets.UTF_8);

    // Utility class. Callers use its static methods.
    private RegistrationCodec() {}

    /**
     * Encodes a registration request as a frame payload.
     *
     * @param request the identity and public keys to encode
     * @return the encoded payload bytes
     * @throws IOException if a field is invalid or encoding fails
     */
    public static byte[] encodeRequest(RegisterRequest request) throws IOException {
        // Restrict identities to the characters defined by the protocol.
        if (!request.identity().matches("[A-Za-z0-9_-]+")) {
            throw new IOException("Identity must contain letters, digits, underscores or hyphens");
        }

        // Convert the identity and public keys into their byte representation.
        byte[] identityBytes = request.identity().getBytes(StandardCharsets.UTF_8);
        byte[] signingKeyBytes = request.signingPublicKey().getEncoded();
        byte[] encryptionKeyBytes = request.encryptionPublicKey().getEncoded();

        // Collect the encoded fields in memory.
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            // Write the identity first.
            Fields.write(out, identityBytes, MAX_IDENTITY_BYTES);

            // Write the Ed25519 public key second.
            Fields.write(out, signingKeyBytes, MAX_PUBLIC_KEY_BYTES);

            // Write the RSA public key third.
            Fields.write(out, encryptionKeyBytes, MAX_PUBLIC_KEY_BYTES);
        }

        // Return the completed payload for FrameCodec to send.
        return buffer.toByteArray();
    }

    /**
     * Decodes a registration request from a frame payload.
     *
     * @param payload the received payload bytes
     * @return the reconstructed registration request
     * @throws IOException if the payload or public keys are invalid
     */
    public static RegisterRequest decodeRequest(byte[] payload) throws IOException {
        // Read the payload already collected by FrameCodec.
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {

            // Read the identity and enforce the same rules as the encoder.
            byte[] identBytes = Fields.read(in, MAX_IDENTITY_BYTES);
            String identity = new String(identBytes, StandardCharsets.UTF_8);

            if (!identity.matches("[A-Za-z0-9_-]+")) {
                throw new IOException("Invalid registration identity");
            }

            // Read the public keys in the order defined by the encoder.
            byte[] signingKeyBytes = Fields.read(in, MAX_PUBLIC_KEY_BYTES);
            byte[] encryptionKeyBytes = Fields.read(in, MAX_PUBLIC_KEY_BYTES);

            // Reject additional bytes behond the three defined fields.
            if (in.read() != -1) {
                throw new IOException("Unexpected bytes after registration request");
            }

            // Reconstruct the Ed25519 key using the existing helper.
            PublicKey signingPublicKey = Signatures.decodePublicKey(signingKeyBytes);

            // Instantiate a factory and reconstruct the RSA public key.
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encryptionKeyBytes);
            PublicKey encryptionPublicKey = keyFactory.generatePublic(keySpec);

            // Collect the encoded fields in the registration request record.
            return new RegisterRequest(identity, signingPublicKey, encryptionPublicKey);

        } catch (GeneralSecurityException e) {
            // Report an undecodable key as an invalid protocol payload.
            throw new IOException("Invalid registration public key", e);
        }
    }

    /**
     * Builds the bytes signed and verified for a registration proof.
     *
     * @param requestPayload the original encoded registration request
     * @param challenge the challenge received from or generated by the relay
     * @return the bytes covered by the registration signature
     * @throws IOException if a field length is invalid or encoding fails
     */
    public static byte[] buildProofData(byte[] requestPayload, byte[] challenge) throws IOException {
        // Require the exact challenge length defined by the protocol.
        if (challenge == null || challenge.length != ProtocolConfig.CHALLENGE_BYTES) {
            throw new IOException("Invalid registration challenge length");
        }

        // Collect the signature input in memory.
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            // Bind the signature to this protocol operation and version.
            Fields.write(out, PROOF_CONTEXT, PROOF_CONTEXT.length);

            // Include the exact request bytes containing the identity and both keys.
            Fields.write(out, requestPayload, MAX_REQUEST_BYTES);

            // Bind the proof to this registration attempt.
            Fields.write(out, challenge, ProtocolConfig.CHALLENGE_BYTES);
        }

        return buffer.toByteArray();
    }
}
