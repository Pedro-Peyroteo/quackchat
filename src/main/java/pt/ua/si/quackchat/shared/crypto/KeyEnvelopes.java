package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;

public class KeyEnvelopes {
    // RSA modulus size chosen for approximately 128-bit classical security.
    // Reference: NIST SP 800-57 Part 1 Rev. 5, Table 2.
    private static final int RSA_KEY_SIZE = 3_072;

    // Use RSA-OAEP to protect AES message keys.
    // ECB is Java's RSA mode name; message content uses AES-GCM.
    private static final String RSA_TRANSFORMATION =
            "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    // An RSA ciphertext occupies the modulus size in bytes: 3,072 / 8 = 384.
    public static final int WRAPPED_KEY_BYTES = RSA_KEY_SIZE / Byte.SIZE;

    private static final OAEPParameterSpec OAEP_PARAMETERS =
            new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );

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

    /**
     * Encrypts a message key for its recipient.
     *
     * @param messageKey the AES key used to encrypt the message
     * @param recipientPublicKey the recipient's RSA public key
     * @return the encrypted key envelope
     * @throws GeneralSecurityException if the key is invalid or wrapping fails
     */
    public static byte[] wrap(SecretKey messageKey, PublicKey recipientPublicKey)
            throws GeneralSecurityException {
        MessageEncryption.validateKey(messageKey);

        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.WRAP_MODE, recipientPublicKey, OAEP_PARAMETERS);

        // Encrypt the AES key using the recipient's RSA public key.
        return cipher.wrap(messageKey);
    }

    /**
     * Recovers the message key using the recipient's private key.
     *
     * @param wrappedKey the received encrypted key envelope
     * @param recipientPrivateKey the recipient's RSA private key
     * @return the recovered AES-128 key
     * @throws GeneralSecurityException if unwrapping fails or the key is invalid
     */
    public static SecretKey unwrap(byte[] wrappedKey, PrivateKey recipientPrivateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.UNWRAP_MODE, recipientPrivateKey, OAEP_PARAMETERS);

        // Recover the encrypted bytes as an AES secret-byte object.
        SecretKey messageKey = (SecretKey) cipher.unwrap( wrappedKey, "AES", Cipher.SECRET_KEY);

        // Enforce the same AES key size used by the sender.
        MessageEncryption.validateKey(messageKey);
        return messageKey;
    }
}
