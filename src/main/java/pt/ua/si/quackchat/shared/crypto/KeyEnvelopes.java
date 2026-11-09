package pt.ua.si.quackchat.shared.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyEnvelopes {
    // RSA modulus size chosen for approximately 128-bit classical security.
    // Reference: NIST SP 800-57 Part 1 Rev. 5, Table 2.
    private static final int RSA_KEY_SIZE = 3_072;

    // Utility class. Callers use its static methods.
    private KeyEnvelopes() {}

    /**
     * Generates an RSA key pair for protecting message keys.
     *
     * @return a matching RSA public and private key pair
     * @throws NoSuchAlgorithmException if RSA is unavailable
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Instantiate Java's RSA key pair generator.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        // Explicitly configure the key size used by the protocol.
        generator.initialize(RSA_KEY_SIZE);

        // Generate the recipient's public and private keys.
        return generator.generateKeyPair();
    }

}
