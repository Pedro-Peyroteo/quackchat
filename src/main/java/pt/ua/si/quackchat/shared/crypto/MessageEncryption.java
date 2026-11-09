package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

public final class MessageEncryption {
    // AES-128 uses a 16-byte key.
    static final int KEY_BYTES  = 16;

    // GCM parameters used by the message format.
    public static final int NONCE_BYTES = 12;
    public static final int TAG_BYTES = 16;

    private static final SecureRandom RANDOM = new SecureRandom();

    private MessageEncryption(){}

    /**
     * Generates a fresh AES key for one message.
     *
     * @return the generated AES-128 key
     * @throws GeneralSecurityException if key generation fails
     */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");

        // KeyGenerator accepts the key size in bits.
        generator.init(KEY_BYTES * Byte.SIZE);

        return generator.generateKey();
    }

    /**
     * Generates a fresh nonce for message encryption.
     *
     * @return the random nonce bytes
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    /**
     * Encrypts and authenticates message content.
     *
     * @param plaintext the content to encrypt
     * @param key the fresh AES key for this message
     * @param nonce the nonce, which must not repeat with the same key
     * @param associatedData the metadata to authenticate without encrypting
     * @return the ciphertext followed by its authentication tag
     * @throws GeneralSecurityException if parameters are invalid or encryption fails
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key,
                                 byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        validateParameters(key, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // GCMParameterSpec accepts the authenticated tag size in bits.
        GCMParameterSpec parameters = new GCMParameterSpec(TAG_BYTES * Byte.SIZE, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameters);

        // Authenticate metadata before processing the message content.
        cipher.updateAAD(associatedData);

        // Java appends the GCM authentication tag to the ciphertext.
        return cipher.doFinal(plaintext);
    }

    /**
     * Authenticates and decrypts message content.
     *
     * @param ciphertext the encrypted content including its authentication tag
     * @param key the recovered AES key
     * @param nonce the nonce received with the message
     * @param associatedData the exact metadata authenticated by the sender
     * @return the plaintext after successful authentication
     * @throws GeneralSecurityException if authentication or decryption fails
     */
    public static byte[] decrypt(byte[] ciphertext, SecretKey key,
                                 byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        validateParameters(key, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameters = new GCMParameterSpec(TAG_BYTES * Byte.SIZE, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, parameters);

        // The recipient must supply exactly the same associated data.
        cipher.updateAAD(associatedData);

        // Return plaintext only after the authentication tag has been verified.
        // If verification fails, doFinal throws AEADBadTagException.
        return cipher.doFinal(ciphertext);
    }

    /**
     * Enforces the AES key format used by message encryption and key envelopes.
     */
    static void validateKey(SecretKey key) throws InvalidKeyException {
        if (key == null || !"AES".equals(key.getAlgorithm())) {
            throw new InvalidKeyException("Expected an AES key");
        }

        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length != KEY_BYTES) {
            throw new InvalidKeyException("Expected a 128-bit AES key");
        }
    }

    /**
     * Validates the key and nonce before initializing GCM.
     */
    private static void validateParameters(SecretKey key, byte[] nonce)
            throws GeneralSecurityException {
        validateKey(key);

        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new InvalidAlgorithmParameterException(
                    "Expected a 12-byte GCM nonce");
        }
    }
}
