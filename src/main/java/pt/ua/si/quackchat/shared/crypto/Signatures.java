package pt.ua.si.quackchat.shared.crypto;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;


public class Signatures {
    /**
     * Generates a new Ed25519 key pair for signing and verification.
     *
     * @return a matching public and private key pair
     * @throws NoSuchAlgorithmException if Ed25519 is unavailable
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Instantiate Java's Ed25519 key pair generator.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");

        // Create a new matching pair of public and private keys.
        return generator.generateKeyPair();
    }

    /**
     * Signs the supplied bytes using an Ed25519 private key.
     *
     * @param data the exact bytes to sign
     * @param privateKey the signer's Ed25519 private key
     * @return the signature bytes
     * @throws GeneralSecurityException if signing fails
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        // Instantiate Java's Ed25519 signature implementation.
        Signature signer = Signature.getInstance("Ed25519");

        // Initialize signing with the owner's private key.
        signer.initSign(privateKey);

        // Supply the bytes that the signature will protect.
        signer.update(data);

        // Generate and return the signature.
        return signer.sign();
    }

    /**
     * Verifies an Ed25519 signature against the supplied bytes.
     *
     * @param data the exact bytes being verified
     * @param signatureBytes the signature received from the signer
     * @param publicKey the signer's Ed25519 public key
     * @return true if the signature matches the data and public key
     * @throws GeneralSecurityException if verification cannot be performed
     */
    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws GeneralSecurityException {
        // Instantiate Java's Ed25519 signature implementation.
        Signature verifier = Signature.getInstance("Ed25519");

        // Initialize verification with the signer's public key.
        verifier.initVerify(publicKey);

        // Supply the bytes that should be covered by the signature.
        verifier.update(data);

        // Check the received signature against those bytes.
        return verifier.verify(signatureBytes);
    }

    /**
     * Reconstructs an Ed25519 public key from its X.509 encoding.
     *
     * @param encodedKey the encoded public key bytes
     * @return the reconstructed public key
     * @throws GeneralSecurityException if the key cannot be decoded
     */
    public static PublicKey decodePublicKey(byte[] encodedKey) throws GeneralSecurityException {
        // Instantiate a factory for Ed25519 keys.
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");

        // Describe the supplied bytes as an X.509-encoded public key.
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);

        // Reconstruct a public key object from the encoded key material.
        return keyFactory.generatePublic(keySpec);
    }
}


