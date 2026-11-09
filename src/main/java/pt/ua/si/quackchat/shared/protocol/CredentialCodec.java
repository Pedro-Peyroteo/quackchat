package pt.ua.si.quackchat.shared.protocol;

import pt.ua.si.quackchat.shared.crypto.Signatures;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;

public final  class CredentialCodec {
    // Separate credential signatures from registration proofs and messages.
    private static final byte[] CONTEXT =
            "QuackChat:credential:v1".getBytes(StandardCharsets.UTF_8);

    // Ed25519 signatures always contain 64 bytes.
    private static final int SIGNATURE_BYTES = 64;

    // Fixed context, issuance time, bounded registration and signature.
    private static final int MAX_PAYLOAD_BYTES =
            CONTEXT.length + Long.BYTES
                    + RegistrationCodec.MAX_REQUEST_BYTES + SIGNATURE_BYTES;

    private CredentialCodec() {}

    /**
     * Creates a credential signed by the relay.
     *
     * @param registration the registration whose proof was verified
     * @param relayPrivateKey the relay's signing key
     * @return the complete signed credential payload
     * @throws IOException if encoding fails
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] issue(RegisterRequest registration,
                               PrivateKey relayPrivateKey) throws IOException, GeneralSecurityException {
        byte[] registrationBytes = RegistrationCodec.encodeRequest(registration);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            // Bind the signature to the credential format and version.
            out.write(CONTEXT);

            // Record the relay's issuance time in UTC epoch milliseconds.
            out.writeLong(Instant.now().toEpochMilli());

            // Include the identity and both public keys.
            out.write(registrationBytes);
        }

        byte[] signedData = buffer.toByteArray();
        byte[] signature = Signatures.sign(signedData, relayPrivateKey);

        if (signature.length != SIGNATURE_BYTES) {
            throw new IOException("Unexpected credential signature length");
        }

        // Copy the signed data and reserve space for the signature at the end.
        byte[] payload = Arrays.copyOf(
                signedData, signedData.length + signature.length);

        // Append the signature immediately after the signed data.
        System.arraycopy(signature, 0, payload,
                signedData.length, signature.length);

        return payload;
    }

    /**
     * Verifies a credential before returning its decoded contents.
     *
     * @param payload the complete signed credential payload
     * @param trustedRelayKey the previously trusted relay public key
     * @return the verified credential contents
     * @throws IOException if the credential is malformed or its signature is invalid
     * @throws GeneralSecurityException if verification cannot be performed
     */
    public static Credential verify(byte[] payload, PublicKey trustedRelayKey)
            throws IOException, GeneralSecurityException {
        // Require room for the fixed fields and a nonempty registration.
        int fixedBytes = CONTEXT.length + Long.BYTES + SIGNATURE_BYTES;
        if (payload == null || payload.length <= fixedBytes
                || payload.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("Invalid credential length");
        }

        // The final 64 bytes are the signature; all preceding bytes are signed.
        int signatureOffset = payload.length - SIGNATURE_BYTES;
        byte[] signedData = Arrays.copyOfRange(payload, 0, signatureOffset);
        byte[] signature = Arrays.copyOfRange(
                payload, signatureOffset, payload.length);

        // Verify the original received bytes before accepting their contents.
        if (!Signatures.verify(signedData, signature, trustedRelayKey)) {
            throw new IOException("Invalid relay credential signature");
        }

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(signedData))) {
            byte[] context = new byte[CONTEXT.length];
            in.readFully(context);

            if (!Arrays.equals(context, CONTEXT)) {
                throw new IOException("Unexpected credential context");
            }

            long issuedAtMillis = in.readLong();
            if (issuedAtMillis <= 0) {
                throw new IOException("Invalid credential issuance time");
            }

            // Reuse the existing identity and public-key validation.
            RegisterRequest registration =
                    RegistrationCodec.decodeRequest(in.readAllBytes());

            return new Credential(
                    registration, Instant.ofEpochMilli(issuedAtMillis));
        }
    }
}
