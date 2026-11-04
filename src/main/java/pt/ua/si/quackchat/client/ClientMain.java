package pt.ua.si.quackchat.client;

import java.io.IOException;
import java.net.Socket;

/**
 * TODO:
 * - Read socket host and port from config or params
 * -
 */

public class ClientMain {
    public static void main(String[] args) throws IOException {
        // Connect to relay.
        try (Socket conn = new Socket("localhost", 5000)){
            System.out.println("[*] Connected to relay");
        }
    }
}
