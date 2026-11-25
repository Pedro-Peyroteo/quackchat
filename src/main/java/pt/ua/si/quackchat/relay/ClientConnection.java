package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;
import pt.ua.si.quackchat.shared.protocol.MessageType;

import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Serializes complete outgoing frames for one client connection.
 */
public final class ClientConnection {
    private final Socket socket;
    private final DataOutputStream out;
    private boolean failed;

    public ClientConnection(Socket socket, DataOutputStream out) {
        this.socket = socket;
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

    /**
     * Tells the client why the connection is ending, then closes it.
     *
     * Called from another session's thread. Closing the socket makes this
     * connection's own reading thread stop with a SocketException.
     *
     * @param reason the error text sent to the client
     */
    public void close(String reason) {
        try {
            send(new Frame(MessageType.ERROR, reason.getBytes(StandardCharsets.UTF_8)));
        } catch (IOException e) {
            // The client may already be gone; closing is all that is left.
        }

        try {
            socket.close();
        } catch (IOException e) {
            // Nothing useful to do if closing fails.
        }
    }
}
