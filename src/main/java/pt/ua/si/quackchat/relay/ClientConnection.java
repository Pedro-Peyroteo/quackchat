package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;

import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Serializes complete outgoing frames for one client connection.
 */
public final class ClientConnection {
    private final DataOutputStream out;
    private boolean failed;

    public ClientConnection(DataOutputStream out) {
        this.out = out;
    }

    /**
     * Writes and flushes one complete frame without interleaving other writers.
     *
     * @param frame the frame to send
     * @throws IOException if this connection cannot send the frame
     */
    public synchronized void send(Frame frame) throws IOException {
        // synchronized means only one thread at a time can execute send() on this connection object.

        if (failed) {
            throw new IOException("Connection writer has failed");
        }

        try {
            FrameCodec.write(out, frame);
            out.flush();
        } catch (IOException e) {
            // A partial write may have damaged framing; stop using this writer.
            failed = true;
            throw e;
        }
    }
}
