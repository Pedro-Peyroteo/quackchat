package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;
import pt.ua.si.quackchat.shared.protocol.MessageType;
import pt.ua.si.quackchat.shared.protocol.ProtocolConfig;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.Socket;

/**
 * Handles a single relay protocol session with a connected client.
 *
 * A relay session consists of a simple request-response exchange:
 * the client sends an empty {@link MessageType#PING} frame and the
 * relay replies with an empty {@link MessageType#PONG} frame.
 *
 * This class is implemented as a utility class and cannot be
 * instantiated.
 */
public final class RelaySession {
    /**
     * Prevents instantiation of this utility class.
     */
    private RelaySession() {}
    /**
     * Processes a single client connection.
     *
     * The method configures the socket read timeout, reads a frame
     * from the client, validates that it is an empty
     * {@link MessageType#PING} frame, and responds with an empty
     * {@link MessageType#PONG} frame.
     *
     * If the received frame does not conform to the protocol,
     * an {@link IOException} is thrown and the session is terminated.
     *
     * @param conn the connected client socket
     * @throws IOException if an I/O error occurs while reading or writing
     *                     frames, if a timeout occurs, or if the received
     *                     frame is not a valid empty PING request
     */
    public static void handle(Socket conn) throws IOException {
        conn.setSoTimeout(ProtocolConfig.READ_TIMEOUT_MILLIS);

        try (
                DataInputStream in = new DataInputStream(conn.getInputStream());
                DataOutputStream out = new DataOutputStream(conn.getOutputStream())
        ) {
            while (true) {
                Frame request = FrameCodec.read(in);

                if (request.type() != MessageType.PING || request.payload().length != 0) {
                    throw new IOException("Expected an empty PING frame");
                }

                FrameCodec.write(out, new Frame(MessageType.PONG, new byte[0]));
                out.flush();
            }
        } catch (EOFException e) {
            // The incoming stream ended. Finish this session.
        }
    }
}
