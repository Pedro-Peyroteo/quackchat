package pt.ua.si.quackchat.shared.protocol;

import java.io.IOException;


public enum MessageType {
    // Each constant call the constructor with its protocol code.
    PING(1),
    PONG(2);

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
