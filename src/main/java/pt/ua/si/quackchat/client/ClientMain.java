package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;
import pt.ua.si.quackchat.shared.protocol.MessageType;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * TODO:
 * - Read socket host and port from config or params
 * -
 */

public class ClientMain {
    public static void main(String[] args) throws IOException {
        try (
                // Connect to the relay on this computer.
                Socket conn = new Socket("localhost", 5000);

                // Wrap the connection's incoming and outgoing bytes.
                DataInputStream in = new DataInputStream(conn.getInputStream());
                DataOutputStream out = new DataOutputStream(conn.getOutputStream())
        ){
            System.out.println("[*] Connected to relay");

            // Create a PING frame with an empty payload.
            Frame request = new Frame(MessageType.PING, new byte[0]);
            FrameCodec.write(out, request);
            out.flush();

            System.out.println("[*] Sent PING");

            // Wait for and decode one response frame.
            Frame response = FrameCodec.read(in);

            // Validate if the relay returned the expected response.
            if(response.type() != MessageType.PONG || response.payload().length != 0) {
                throw new IOException("Expected an empty PONG frame");
            }

            System.out.println("[*] Received PONG");
        }
        // The socket and its streams are closed.
    }
}
