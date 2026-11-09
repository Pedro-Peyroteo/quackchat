package pt.ua.si.quackchat.shared.protocol;

import java.time.Instant;
import java.util.Objects;

/**
 * Contains the identity, public keys and issuance time certified by the relay.
 */
public record Credential(RegisterRequest registration, Instant issuedAt) {
    public Credential {
        Objects.requireNonNull(registration, "registration");
        Objects.requireNonNull(issuedAt, "issuedAt");
    }
}