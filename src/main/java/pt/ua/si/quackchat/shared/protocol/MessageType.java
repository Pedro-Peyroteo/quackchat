package pt.ua.si.quackchat.shared.protocol;

import java.io.IOException;


public enum MessageType {
    // Check that a connection can exchange frames.
    PING(1),
    PONG(2),

    // Submit the client's identity and public keys.
    REGISTER_REQUEST(3),

    // Challenge the client to prove possession of its signing key.
    REGISTER_CHALLENGE(4),

    // Return the client's signature over the registration proof data.
    REGISTER_PROOF(5),

    // Return the relay-signed registration credential.
    REGISTER_SUCCESS(6),

    // Report a rejected request.
    ERROR(7);

    // Store the code that belongs to this enum constant.
    // final prevents reassignment after construction.
    private final int code;

    MessageType(int code) {
        this.code = code;
    }

    // Return this constant's numeric protocol code.
    public int code() {
        return code;
    }

    // static permits calling MessageType.fromCode() directly.
    public static MessageType fromCode(int code) throws IOException {
        // Iterate enum values to match the code provided.
        // values() supplies all the enum values.
        for (MessageType type : values()) {
            if (type.code == code) {
                return type;
            }
        }

        throw new IOException("Unknown message type: " + code);
    }
}
