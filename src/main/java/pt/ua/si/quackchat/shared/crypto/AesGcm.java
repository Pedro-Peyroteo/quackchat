package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

/**
 * AES-GCM shared by message encryption and password-based encryption.
 *
 * Each caller states the key size it requires, so message keys stay
 * 128-bit and password-derived keys stay 256-bit.
 */
final class AesGcm {
    // GCM parameters used by every QuackChat format.
    static final int NONCE_BYTES = 12;
    static final int TAG_BYTES = 16;

    private AesGcm() {}

    /**
     * Encrypts and authenticates data.
     *
     * @return the ciphertext followed by its authentication tag
     */
    static byte[] encrypt(byte[] plaintext, SecretKey key, int keyBytes,
                          byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, key, keyBytes, nonce);

        // Authenticate metadata before processing the content.
        cipher.updateAAD(associatedData);
        return cipher.doFinal(plaintext);
    }

    /**
     * Authenticates and decrypts data.
     *
     * @throws javax.crypto.AEADBadTagException if authentication fails
     */
    static byte[] decrypt(byte[] ciphertext, SecretKey key, int keyBytes,
                          byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, key, keyBytes, nonce);

        // The recipient must supply exactly the same associated data.
        cipher.updateAAD(associatedData);

        // Returns plaintext only after the tag has been verified.
        return cipher.doFinal(ciphertext);
    }

    /**
     * Requires an AES key of exactly keyBytes.
     */
    static void validateKey(SecretKey key, int keyBytes)
            throws InvalidKeyException {
        if (key == null || !"AES".equals(key.getAlgorithm())) {
            throw new InvalidKeyException("Expected an AES key");
        }

        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length != keyBytes) {
            throw new InvalidKeyException(
                    "Expected a " + keyBytes * Byte.SIZE + "-bit AES key");
        }
    }

    /**
     * Validates the parameters and initializes a GCM cipher.
     */
    private static Cipher initCipher(int mode, SecretKey key, int keyBytes,
                                     byte[] nonce)
            throws GeneralSecurityException {
        validateKey(key, keyBytes);

        if (nonce == null || nonce.length != NONCE_BYTES) {
            throw new InvalidAlgorithmParameterException(
                    "Expected a 12-byte GCM nonce");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // GCMParameterSpec takes the tag size in bits.
        cipher.init(mode, key,
                new GCMParameterSpec(TAG_BYTES * Byte.SIZE, nonce));
        return cipher;
    }
}
