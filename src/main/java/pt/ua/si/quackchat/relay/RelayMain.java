package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.ProtocolConfig;
import java.io.IOException;

/**
 * Entry point for the QuackChat Relay service.
 *
 * This class is responsible for starting a {@link RelayServer}
 * instance on the configured network port and keeping it running
 * to handle incoming relay connections.
 *
 * The listening port can be specified as a command-line argument.
 * If no argument is provided, the default relay port defined in
 * {@link ProtocolConfig#DEFAULT_RELAY_PORT} is used.
 */
public class RelayMain {
    /**
     * Starts the relay server.
     *
     * Accepts an optional command-line argument specifying the
     * listening port. If provided, the port is validated before the
     * server is started.
     *
     * @param args command-line arguments; optionally contains a single
     *             port number
     * @throws IOException if an I/O error occurs while creating or
     *                     running the relay server
     * @throws IllegalArgumentException if more than one argument is
     *                                  supplied or if the port is invalid
     */
    public static void main(String[] args) throws IOException {
        if (args.length > 1) {
            throw new IllegalArgumentException("Usage: RelayMain [port]");
        }

        int port = args.length == 1 ? parsePort(args[0]) : ProtocolConfig.DEFAULT_RELAY_PORT;
        try (RelayServer relay = new RelayServer(port)) {
            System.out.println("[*] Relay listening on port " + relay.port());
            relay.serve();
        }
    }
    /**
     * Parses and validates a port number.
     *
     * The port must be a numeric value within the valid TCP/UDP
     * port range of 1 to 65535.
     *
     * @param value the string representation of the port number
     * @return the validated port number
     * @throws IllegalArgumentException if the value is not numeric or
     *                                  is outside the valid port range
     */
    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65_535) {
                throw new IllegalArgumentException("Port must be between 1 and 65535");
            }
            return port;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Port must be a number between 1 and 65535", e);
        }
    }
}
