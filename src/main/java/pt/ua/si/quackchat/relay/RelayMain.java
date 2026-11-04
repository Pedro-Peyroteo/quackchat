package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;
import pt.ua.si.quackchat.shared.protocol.MessageType;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class RelayMain {
    public static void main(String[] args) throws IOException {
        // Open a listening socket on port 5000.
        try (ServerSocket server = new ServerSocket(5000)){
            System.out.println("[*] Relay listening on port 5000");

            try (
                    // Wait for a client and obtain its connected socket.
                    Socket conn = server.accept();

                    // Wrap the connection's incoming and outgoing bytes.
                    DataInputStream in = new DataInputStream(conn.getInputStream());
                    DataOutputStream out = new DataOutputStream(conn.getOutputStream())
            ) {
                System.out.println("[*] Client connected");

                // Decode one incoming frame.
                Frame request = FrameCodec.read(in);

                // Validate if the request matches this exchange.
                if (request.type() != MessageType.PING || request.payload().length != 0) {
                    throw new IOException("Expected an empty PING frame");
                }

                System.out.println("[*] Received PING");


                // Encode the response and flush pending output.
                Frame response = new Frame(MessageType.PONG, new byte[0]);
                FrameCodec.write(out, response);
                out.flush();

                System.out.println("[*] Sent PONG");
            }
            // Connected socket and its streams are closed.
        }
        // Listening socket is closed.
    }
}
