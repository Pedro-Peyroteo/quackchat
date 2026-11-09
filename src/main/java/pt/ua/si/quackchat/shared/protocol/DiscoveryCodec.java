package pt.ua.si.quackchat.shared.protocol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public final class DiscoveryCodec {
    private DiscoveryCodec() {}

    /**
     * Encodes the identity whose credential is requested.
     *
     * @param identity the target identity
     * @return the discovery request payload
     * @throws java.io.IOException if the identity is invalid
     */
    public static byte[] encodeRequest(String identity) throws IOException {
        validateIdentity(identity);
        return identity.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Decodes a discovery request.
     *
     * @param payload the received identity bytes
     * @return the validated target identity
     * @throws IOException if the payload is invalid
     */
    public static String decodeRequest(byte[] payload) throws IOException {
        // Reject invalid lengths before decoding.
        if (payload == null || payload.length == 0
                || payload.length > RegistrationCodec.MAX_IDENTITY_BYTES) {
            throw new IOException("Invalid discovery identity length");
        }

        String identity = new String(payload, StandardCharsets.UTF_8);
        validateIdentity(identity);
        return identity;
    }

    /**
     * Enforces the identity rules used by registration.
     */
    private static void validateIdentity(String identity) throws IOException {
        // Allowed characters are ASCII, so each occupies one UTF-8 byte.
        if (identity == null || identity.isEmpty()
                || identity.length() > RegistrationCodec.MAX_IDENTITY_BYTES
                || !identity.matches("[A-Za-z0-9_-]+")) {
            throw new IOException("Invalid discovery identity");
        }
    }
}
