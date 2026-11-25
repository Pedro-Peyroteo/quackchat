package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

public final class MessageEncryption {
    // AES-128 uses a 16-byte key.
    static final int KEY_BYTES  = 16;

    // GCM parameters used by the message format.
    public static final int NONCE_BYTES = AesGcm.NONCE_BYTES;
    public static final int TAG_BYTES = AesGcm.TAG_BYTES;

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
        return AesGcm.encrypt(plaintext, key, KEY_BYTES, nonce, associatedData);
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
        // If verification fails, this throws AEADBadTagException.
        return AesGcm.decrypt(ciphertext, key, KEY_BYTES, nonce, associatedData);
    }

    /**
     * Enforces the AES-128 key format used by message encryption and key envelopes.
     */
    static void validateKey(SecretKey key) throws InvalidKeyException {
        AesGcm.validateKey(key, KEY_BYTES);
    }
}
