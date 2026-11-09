package pt.ua.si.quackchat.shared.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.HexFormat;

public class SignaturesCheck {
    /**
     * Displays signing and verification results for three cases.
     *
     * @param args unused command-line arguments
     * @throws GeneralSecurityException if a cryptographic operation fails
     */
    public static void main(String[] args) throws GeneralSecurityException {
        // Generate Alice's signing keys and a separate pair for Bob.
        KeyPair aliceKeys = Signatures.generateKeyPair();
        KeyPair bobKeys = Signatures.generateKeyPair();

        // Convert readable text into the exact bytes to sign.
        byte[] data = "Hello, Bob!".getBytes(StandardCharsets.UTF_8);

        // Display each byte as two hexadecimals digits.
        HexFormat hex = HexFormat.ofDelimiter(" ");
        System.out.println("Original bytes = " + hex.formatHex(data));

        // Sign the original bytes using Alice's private key.
        byte[] signature = Signatures.sign(data, aliceKeys.getPrivate());
        System.out.println("Signature length = " + signature.length);
        System.out.println("Signature bytes = " + hex.formatHex(signature));

        // Check the original data with Alice's matching public key.
        boolean originalValid = Signatures.verify(data, signature, aliceKeys.getPublic());
        System.out.println("Original data + Alice's key = " + originalValid);

        // Copy the data and change the first character from H to 3.
        byte[] changedData = data.clone();
        changedData[0] = (byte) 'J';
        System.out.println("Changed bytes = " + hex.formatHex(changedData));

        // Check the changed data against the original signature.
        boolean changedValid = Signatures.verify(changedData, signature, aliceKeys.getPublic());
        System.out.println("Changed data + Alice's key = " + changedValid);

        // Check the original data using Bob's unrelated public key.
        boolean wrongKeyValid = Signatures.verify(data, signature, bobKeys.getPublic());
        System.out.println("Original data + Bob's key = " + wrongKeyValid);

        // Fail the check if any result differs from the expected.
        if (!originalValid || changedValid || wrongKeyValid) {
            throw new GeneralSecurityException("Unexpected signature verification result.");
        }

        System.out.println("All signature checks passed");
    }
}
