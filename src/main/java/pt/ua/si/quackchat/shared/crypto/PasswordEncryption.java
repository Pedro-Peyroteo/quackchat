package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Derives keys from passwords and protects data with AES-256-GCM.
 *
 * This class defines no storage layout. Callers decide which bytes are
 * encrypted and which are authenticated as associated data.
 */
public final class PasswordEncryption {
    // AES-256 for long-lived data such as private keys (decision D10).
    public static final int KEY_BYTES = 32;

    // NIST SP 800-132 requires at least 128 random bits of salt.
    public static final int SALT_BYTES = 16;

    // OWASP recommendation for PBKDF2-HMAC-SHA256. Always used when saving.
    public static final int DEFAULT_ITERATIONS = 600_000;

    // Reject weakened files, and counts large enough to stall the program.
    public static final int MIN_ITERATIONS = DEFAULT_ITERATIONS;
    public static final int MAX_ITERATIONS = 10 * DEFAULT_ITERATIONS;

    // Largest output any caller needs: AES and HMAC keys for the relay store.
    public static final int MAX_DERIVED_BYTES = 64;

    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordEncryption() {}

    /**
     * Generates a fresh random salt.
     *
     * @return SALT_BYTES random bytes
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return salt;
    }

    /**
     * Derives key material from a password with PBKDF2-HMAC-SHA256.
     *
     * The caller owns the password array and must wipe it after use.
     *
     * @param password the password; not modified by this method
     * @param salt SALT_BYTES of salt stored next to the protected data
     * @param iterations between MIN_ITERATIONS and MAX_ITERATIONS
     * @param lengthBytes number of bytes to derive, at most MAX_DERIVED_BYTES
     * @return the derived bytes, which the caller should wipe after use
     * @throws InvalidKeySpecException if any parameter is out of range
     * @throws GeneralSecurityException if PBKDF2 is unavailable or fails
     */
    public static byte[] deriveKeyBytes(char[] password, byte[] salt,
                                        int iterations, int lengthBytes)
            throws GeneralSecurityException {
        if (password == null || password.length == 0) {
            throw new InvalidKeySpecException("Password must not be empty");
        }

        if (salt == null || salt.length != SALT_BYTES) {
            throw new InvalidKeySpecException(
                    "Expected a " + SALT_BYTES + "-byte salt");
        }

        // The count may come from a file, so bound it before doing the work.
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new InvalidKeySpecException(
                    "PBKDF2 iteration count out of range: " + iterations);
        }

        if (lengthBytes <= 0 || lengthBytes > MAX_DERIVED_BYTES) {
            throw new InvalidKeySpecException(
                    "Invalid derived key length: " + lengthBytes);
        }

        SecretKeyFactory factory =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

        // PBEKeySpec takes the length in bits and keeps its own password copy.
        PBEKeySpec spec = new PBEKeySpec(
                password, salt, iterations, lengthBytes * Byte.SIZE);

        try {
            return factory.generateSecret(spec).getEncoded();
        } finally {
            // Wipe the spec's copy whether or not derivation succeeded.
            spec.clearPassword();
        }
    }

    /**
     * Encrypts and authenticates data with AES-256-GCM.
     *
     * @param plaintext the data to encrypt
     * @param key a KEY_BYTES AES key
     * @param nonce a fresh 12-byte nonce, never reused with the same key
     * @param associatedData bytes authenticated but not encrypted
     * @return the ciphertext followed by its 16-byte tag
     * @throws GeneralSecurityException if parameters are invalid or encryption fails
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key,
                                 byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        validateParameters(key, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(
                MessageEncryption.TAG_BYTES * Byte.SIZE, nonce));

        cipher.updateAAD(associatedData);
        return cipher.doFinal(plaintext);
    }

    /**
     * Authenticates and decrypts data protected by {@link #encrypt}.
     *
     * @param ciphertext the ciphertext including its tag
     * @param key the same KEY_BYTES AES key used to encrypt
     * @param nonce the nonce used to encrypt
     * @param associatedData the exact bytes authenticated when encrypting
     * @return the plaintext, only if authentication succeeds
     * @throws javax.crypto.AEADBadTagException if the key, nonce,
     *         associated data or ciphertext do not match
     * @throws GeneralSecurityException if parameters are invalid
     */
    public static byte[] decrypt(byte[] ciphertext, SecretKey key,
                                 byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        validateParameters(key, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(
                MessageEncryption.TAG_BYTES * Byte.SIZE, nonce));

        cipher.updateAAD(associatedData);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Validates the key and nonce before initializing GCM.
     */
    private static void validateParameters(SecretKey key, byte[] nonce)
            throws GeneralSecurityException {
        validateKey(key);

        if (nonce == null || nonce.length != MessageEncryption.NONCE_BYTES) {
            throw new InvalidAlgorithmParameterException(
                    "Expected a 12-byte GCM nonce");
        }
    }

    /**
     * Requires an AES key of exactly KEY_BYTES.
     *
     * MessageEncryption keeps its separate 128-bit check for message keys.
     */
    private static void validateKey(SecretKey key) throws InvalidKeyException {
        if (key == null || !"AES".equals(key.getAlgorithm())) {
            throw new InvalidKeyException("Expected an AES key");
        }

        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length != KEY_BYTES) {
            throw new InvalidKeyException("Expected a 256-bit AES key");
        }
    }
}