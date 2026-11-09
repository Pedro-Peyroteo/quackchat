package pt.ua.si.quackchat.shared.protocol;

import java.security.PublicKey;
import java.util.Objects;

public record RegisterRequest(
        String identity,
        PublicKey signingPublicKey,
        PublicKey encryptionPublicKey
) {
    // Compact constructor. Requires all registration fields to be present.
    public RegisterRequest {
        Objects.requireNonNull(identity, "identity");
        Objects.requireNonNull(signingPublicKey, "signingPublicKey");
        Objects.requireNonNull(encryptionPublicKey, "encryptionPublicKey");
    }
}
