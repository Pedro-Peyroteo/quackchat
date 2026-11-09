package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.ProtocolConfig;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Arrays;

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
    public static void main(String[] args) throws IOException, GeneralSecurityException {
        if (args.length > 1) {
            throw new IllegalArgumentException("Usage: RelayMain [port]");
        }

        int port = args.length == 1 ? parsePort(args[0]) : ProtocolConfig.DEFAULT_RELAY_PORT;

        // Read the local keystore password from the relay's run configuration.
        String configuredPassword =
                System.getenv("QUACKCHAT_RELAY_KEYSTORE_PASSWORD");
        if (configuredPassword == null || configuredPassword.isEmpty()) {
            throw new IllegalStateException(
                    "Set QUACKCHAT_RELAY_KEYSTORE_PASSWORD before starting the relay");
        }

        char[] password = configuredPassword.toCharArray();
        PrivateKey relaySigningKey;

        try {
            // Load the persistent relay identity.
            // Use the JDK-supported PKCS#12 format to persist the relay's
            // private key and certificate in a password-protected keystore.
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream keyInput =
                         Files.newInputStream(Path.of("keys/relay.p12"))) {
                keyStore.load(keyInput, password);
            }

            // Retrieve the private key stored under the provisioning alias.
            Key storedKey = keyStore.getKey("relay", password);
            if (!(storedKey instanceof PrivateKey privateKey)) {
                throw new IOException("Relay signing key is missing");
            }

            relaySigningKey = privateKey;
        } finally {
            // Clear the temporary password character array.
            Arrays.fill(password, '\0');
        }

        try (RelayServer relay = new RelayServer(port, relaySigningKey)) {
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
