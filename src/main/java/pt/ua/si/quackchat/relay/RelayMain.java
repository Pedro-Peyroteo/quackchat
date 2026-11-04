package pt.ua.si.quackchat.relay;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class RelayMain {
    public static void main(String[] args) throws IOException {
        try (ServerSocket server = new ServerSocket(5000)){
            System.out.println("[*] Relay listening on port 5000");

            // server.accept() waits for a client connection.
            try (Socket connection = server.accept()) {
                System.out.println("[*] Client connected");
            }
        }
    }
}
