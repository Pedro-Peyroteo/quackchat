package pt.ua.si.quackchat.shared.protocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public final class FrameCodec {
    // Protocol version supported by this implementation.
    private static final int VERSION = 1;

    // Version and type occupy 1 byte each.
    private static final int HEADER_LENGTH = 2;

    // Maximum value permitted in the length field.
    private static final int MAX_FRAME_LENGTH = 65_536;

    // Utility class: callers use its static methods.
    private FrameCodec() {}

    public static void write(DataOutputStream out, Frame frame) throws IOException {
        byte[] payload = frame.payload();

        // Validate before adding, avoiding int overflow.
        if (payload.length > MAX_FRAME_LENGTH - HEADER_LENGTH) {
            throw new IOException("Frame exceeds maximum length");
        }

        int length = HEADER_LENGTH + payload.length;

        // Writes fields in the order defined by the protocol.
        out.writeInt(length);
        out.writeByte(VERSION);
        out.writeByte(frame.type().code());
        out.write(payload);
    }

    public static Frame read(DataInputStream in) throws IOException {
        // Consume the next 4 bytes as the frame length.
        int length = in.readInt();

        // Reject invalid lengths before allocating a payload array.
        if (length < HEADER_LENGTH || length > MAX_FRAME_LENGTH) {
            throw new IOException("Invalid frame length: " + length);
        }

        // Consume 1 byte and interpret it as a number from 0 to 255.
        // Notes:
        //   readByte returns a byte with range: -128 to 127
        //   readByte returns an integer with range: 0 to 255
        int version = in.readUnsignedByte();

        if (version != VERSION) {
            throw new IOException("Unsupported protocol version: " + version);
        }

        // Consume the next byte and resolve its message type.
        MessageType type = MessageType.fromCode(in.readUnsignedByte());

        // The remaining bytes belong to the payload.
        byte[] payload = new byte[length - HEADER_LENGTH];

        // Read the remaining bytes.
        in.readFully(payload);

        return new Frame(type, payload);
    }
}
