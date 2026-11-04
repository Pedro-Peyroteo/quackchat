package pt.ua.si.quackchat.shared.protocol;

import java.util.Objects;

public record Frame(MessageType type, byte[] payload) {
    // Compact constructor. Validates args before Java stores them.
    public Frame {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(payload, "payload");
    }
}