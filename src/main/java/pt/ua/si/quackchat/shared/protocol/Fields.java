package pt.ua.si.quackchat.shared.protocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Writes and reads length-prefixed fields: a big-endian Int32 byte count
 * followed by that many bytes, written F(x) in the architecture document.
 */
public final class Fields {
    // Utility class. Callers use its static methods.
    private Fields() {}

    /**
     * Writes a nonempty field preceded by its length.
     *
     * @param out the destination stream
     * @param value the bytes to write, 1 to maxLength bytes
     * @param maxLength the largest permitted field length
     * @throws IOException if the field is missing, empty or too long,
     *                     or writing fails
     */
    public static void write(DataOutputStream out, byte[] value, int maxLength)
            throws IOException {
        // Refuse to produce a field the reader would reject.
        if (value == null || value.length == 0 || value.length > maxLength) {
            throw new IOException("Invalid field length");
        }

        out.writeInt(value.length);
        out.write(value);
    }

    /**
     * Reads a field, validating its length before allocating it.
     *
     * @param in the source stream
     * @param maxLength the largest permitted field length
     * @return the field's bytes
     * @throws IOException if the length is invalid or data is incomplete
     */
    public static byte[] read(DataInputStream in, int maxLength)
            throws IOException {
        // Check the untrusted length before allocating, so a peer cannot
        // make us allocate an arbitrarily large array.
        int length = in.readInt();
        if (length <= 0 || length > maxLength) {
            throw new IOException("Invalid field length");
        }

        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }
}
