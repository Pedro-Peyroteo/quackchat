package pt.ua.si.quackchat.shared.crypto;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class PasswordEncryptionCheck {
    /**
     * Displays the result of each password encryption check.
     *
     * @param args unused command-line arguments
     * @throws GeneralSecurityException if a check fails unexpectedly
     */
    public static void main(String[] args) throws GeneralSecurityException {
        char[] password = "correct horse battery staple".toCharArray();
        char[] wrongPassword = "correct horse battery stapler".toCharArray();
        byte[] salt = PasswordEncryption.generateSalt();
        int iterations = PasswordEncryption.DEFAULT_ITERATIONS;
        int keyBytes = PasswordEncryption.KEY_BYTES;

        // Time one derivation at the default count (recorded in D10).
        long start = System.nanoTime();
        byte[] keyA = PasswordEncryption.deriveKeyBytes(
                password, salt, iterations, keyBytes);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000;
        System.out.println("Derivation at " + iterations
                + " iterations = " + elapsedMillis + " ms");

        // The same password, salt and count must give the same key.
        byte[] keyB = PasswordEncryption.deriveKeyBytes(
                password, salt, iterations, keyBytes);
        boolean deterministic = Arrays.equals(keyA, keyB);
        System.out.println("Same inputs give the same key = " + deterministic);

        // A different salt must give a different key.
        byte[] keyOtherSalt = PasswordEncryption.deriveKeyBytes(
                password, PasswordEncryption.generateSalt(), iterations, keyBytes);
        boolean saltChangesKey = !Arrays.equals(keyA, keyOtherSalt);
        System.out.println("Different salt gives a different key = " + saltChangesKey);

        // Encrypt and decrypt with the derived key.
        SecretKey key = new SecretKeySpec(keyA, "AES");
        byte[] nonce = MessageEncryption.generateNonce();
        byte[] associatedData = "QCID header".getBytes(StandardCharsets.UTF_8);
        byte[] plaintext = "private key material".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = PasswordEncryption.encrypt(
                plaintext, key, nonce, associatedData);
        byte[] decrypted = PasswordEncryption.decrypt(
                ciphertext, key, nonce, associatedData);
        boolean roundTrip = Arrays.equals(plaintext, decrypted);
        System.out.println("Round trip restores the plaintext = " + roundTrip);

        // A key derived from a different password must fail authentication.
        SecretKey wrongKey = new SecretKeySpec(PasswordEncryption.deriveKeyBytes(
                wrongPassword, salt, iterations, keyBytes), "AES");
        boolean wrongPasswordRejected = rejectsDecryption(
                ciphertext, wrongKey, nonce, associatedData);
        System.out.println("Wrong password rejected = " + wrongPasswordRejected);

        // Flip one bit of the associated data.
        byte[] changedAssociatedData = associatedData.clone();
        changedAssociatedData[0] ^= 1;
        boolean associatedDataRejected = rejectsDecryption(
                ciphertext, key, nonce, changedAssociatedData);
        System.out.println("Changed associated data rejected = " + associatedDataRejected);

        // Flip one bit of the ciphertext.
        byte[] changedCiphertext = ciphertext.clone();
        changedCiphertext[0] ^= 1;
        boolean ciphertextRejected = rejectsDecryption(
                changedCiphertext, key, nonce, associatedData);
        System.out.println("Changed ciphertext rejected = " + ciphertextRejected);

        // Invalid parameters must be refused before any work is done.
        boolean lowIterationsRejected = rejectsDerivation(
                password, salt, PasswordEncryption.MIN_ITERATIONS - 1);
        boolean shortSaltRejected = rejectsDerivation(
                password, new byte[PasswordEncryption.SALT_BYTES - 1], iterations);
        boolean shortKeyRejected = rejectsKey(
                new SecretKeySpec(new byte[16], "AES"), nonce, plaintext, associatedData);
        System.out.println("Low iteration count rejected = " + lowIterationsRejected);
        System.out.println("Short salt rejected = " + shortSaltRejected);
        System.out.println("128-bit key rejected = " + shortKeyRejected);

        Arrays.fill(password, '\0');
        Arrays.fill(wrongPassword, '\0');

        // Fail the check if any result differs from the expected.
        if (!deterministic || !saltChangesKey || !roundTrip
                || !wrongPasswordRejected || !associatedDataRejected
                || !ciphertextRejected || !lowIterationsRejected
                || !shortSaltRejected || !shortKeyRejected) {
            throw new GeneralSecurityException(
                    "Unexpected password encryption result.");
        }

        System.out.println("All password encryption checks passed");
    }

    /**
     * Returns true only if decryption fails GCM authentication.
     */
    private static boolean rejectsDecryption(byte[] ciphertext, SecretKey key,
                                             byte[] nonce, byte[] associatedData)
            throws GeneralSecurityException {
        try {
            PasswordEncryption.decrypt(ciphertext, key, nonce, associatedData);
            return false;
        } catch (AEADBadTagException e) {
            return true;
        }
    }

    /**
     * Returns true only if derivation refuses its parameters.
     */
    private static boolean rejectsDerivation(char[] password, byte[] salt,
                                             int iterations)
            throws GeneralSecurityException {
        try {
            PasswordEncryption.deriveKeyBytes(
                    password, salt, iterations, PasswordEncryption.KEY_BYTES);
            return false;
        } catch (InvalidKeySpecException e) {
            return true;
        }
    }

    /**
     * Returns true only if encryption refuses the key.
     */
    private static boolean rejectsKey(SecretKey key, byte[] nonce,
                                      byte[] plaintext, byte[] associatedData)
            throws GeneralSecurityException {
        try {
            PasswordEncryption.encrypt(plaintext, key, nonce, associatedData);
            return false;
        } catch (InvalidKeyException e) {
            return true;
        }
    }
}