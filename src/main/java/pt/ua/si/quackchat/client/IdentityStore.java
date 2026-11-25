package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.crypto.MessageEncryption;
import pt.ua.si.quackchat.shared.crypto.PasswordEncryption;
import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.Credential;
import pt.ua.si.quackchat.shared.protocol.CredentialCodec;
import pt.ua.si.quackchat.shared.protocol.DiscoveryCodec;
import pt.ua.si.quackchat.shared.protocol.Fields;
import pt.ua.si.quackchat.shared.protocol.RegistrationCodec;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * Saves and loads a client's identity in a password-encrypted file.
 *
 * Layout: a 37-byte cleartext header, authenticated as GCM
 *         associated data, followed by the AES-256-GCM encryption of
 *         F(identity) || F(credential) || F(Ed25519 PKCS#8) || F(RSA PKCS#8).
 *
 * Header: magic "QCID" (4), version (1), PBKDF2 iterations (4),
 * salt (16), GCM nonce (12).
 */
public final class IdentityStore {
    private static final byte[] MAGIC = {'Q', 'C', 'I', 'D'};
    private static final int VERSION = 1;

    // magic + version + iterations + salt + nonce = 4 + 1 + 4 + 16 + 12 = 37
    private static final int HEADER_BYTES = MAGIC.length + 1 + Integer.BYTES
            + PasswordEncryption.SALT_BYTES + MessageEncryption.NONCE_BYTES;

    // RSA-3072 PKCS#8 is about 1.8 KB; Ed25519 is 48 bytes.
    private static final int MAX_PRIVATE_KEY_BYTES = 4_096;

    // Refuse to read anything larger than a real identity file could be.
    private static final int MAX_FILE_BYTES = 16_384;

    private static final String DIRECTORY = "clients";
    private static final String FILE_NAME = "identity.bin";

    private static final SecureRandom RANDOM = new SecureRandom();

    private IdentityStore() {}

    /**
     * Returns clients/&lt;identity&gt;/identity.bin, after validating the identity.
     *
     * @param identity the client identity
     * @return the identity file path, relative to the working directory
     * @throws IOException if the identity contains characters outside
     *                     [A-Za-z0-9_-]
     */
    public static Path pathFor(String identity) throws IOException {
        // Restricting the characters stops names such as "../keys"
        // from placing the file outside the clients directory (path traversal).
        DiscoveryCodec.encodeRequest(identity);

        return Path.of(DIRECTORY, identity, FILE_NAME);
    }

    /**
     * Encrypts and writes a new identity file.
     *
     * The caller owns the password array and must wipe it after use.
     *
     * @param file where to write the file; must not exist yet
     * @param identity the identity, credential and key pairs to store
     * @param password the password protecting the file
     * @throws FileAlreadyExistsException if the file already exists
     * @throws IOException if encoding or writing fails
     * @throws GeneralSecurityException if key derivation or encryption fails
     */
    public static void save(Path file, ClientIdentity identity, char[] password)
            throws IOException, GeneralSecurityException {
        // The file holds the only copy of the private keys.
        if (Files.exists(file)) {
            throw new FileAlreadyExistsException(file.toString());
        }

        // New salt and nonce on every save; always the current iteration count.
        byte[] salt = PasswordEncryption.generateSalt();
        byte[] nonce = MessageEncryption.generateNonce();
        byte[] header = encodeHeader(
                PasswordEncryption.DEFAULT_ITERATIONS, salt, nonce);

        byte[] plaintext = encodePlaintext(identity);
        byte[] ciphertext;
        try {
            SecretKey key = deriveKey(
                    password, salt, PasswordEncryption.DEFAULT_ITERATIONS);

            // The header is authenticated but stays readable.
            ciphertext = PasswordEncryption.encrypt(plaintext, key, nonce, header);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }

        byte[] contents = Arrays.copyOf(header, header.length + ciphertext.length);
        System.arraycopy(ciphertext, 0, contents, header.length, ciphertext.length);

        // Write a temporary file, then move it into place in one step,
        // so a crash never leaves a half-written identity file.
        Files.createDirectories(file.toAbsolutePath().getParent());
        Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
        Files.write(temporary, contents);
        Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Reads, decrypts and checks an identity file.
     *
     * Nothing from the file is used before it has been authenticated:
     * the header and contents by AES-GCM, the credential by the relay's
     * signature, and the private keys by matching them against the
     * credential's public keys.
     *
     * @param file the identity file
     * @param expectedIdentity the identity the user asked to start as
     * @param password the password protecting the file; caller wipes it
     * @param trustedRelayKey the relay public key from keys/relay.cer
     * @return the verified identity
     * @throws AEADBadTagException if the password is wrong or the file was modified
     * @throws IOException if the file is malformed or belongs to another identity
     * @throws GeneralSecurityException if a cryptographic check fails
     */
    public static ClientIdentity load(Path file, String expectedIdentity,
                                      char[] password, PublicKey trustedRelayKey)
            throws IOException, GeneralSecurityException {
        // Check the size before reading the whole file into memory.
        if (Files.size(file) > MAX_FILE_BYTES) {
            throw new IOException("Identity file is too large");
        }

        byte[] contents = Files.readAllBytes(file);
        if (contents.length < HEADER_BYTES + MessageEncryption.TAG_BYTES) {
            throw new IOException("Identity file is too short");
        }

        byte[] header = Arrays.copyOf(contents, HEADER_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(contents, HEADER_BYTES, contents.length);

        int iterations;
        byte[] salt = new byte[PasswordEncryption.SALT_BYTES];
        byte[] nonce = new byte[MessageEncryption.NONCE_BYTES];

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(header))) {
            byte[] magic = new byte[MAGIC.length];
            in.readFully(magic);
            if (!Arrays.equals(magic, MAGIC)) {
                throw new IOException("Not a QuackChat identity file");
            }

            int version = in.readUnsignedByte();
            if (version != VERSION) {
                throw new IOException("Unsupported identity file version: " + version);
            }

            iterations = in.readInt();
            in.readFully(salt);
            in.readFully(nonce);
        }

        byte[] plaintext;
        try {
            // deriveKeyBytes rejects an out-of-range iteration count
            // before doing any work.
            SecretKey key = deriveKey(password, salt, iterations);
            plaintext = PasswordEncryption.decrypt(ciphertext, key, nonce, header);
        } catch (AEADBadTagException e) {
            // GCM cannot tell a wrong password from a modified file.
            AEADBadTagException failure = new AEADBadTagException(
                    "Wrong password or damaged identity file");
            failure.initCause(e);
            throw failure;
        }

        String storedIdentity;
        byte[] credentialBytes;
        PrivateKey signingPrivate;
        PrivateKey encryptionPrivate;
        byte[] signingKeyBytes = null;
        byte[] encryptionKeyBytes = null;

        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(plaintext))) {
            storedIdentity = new String(
                    Fields.read(in, RegistrationCodec.MAX_IDENTITY_BYTES),
                    StandardCharsets.UTF_8);
            credentialBytes = Fields.read(in, CredentialCodec.MAX_PAYLOAD_BYTES);
            signingKeyBytes = Fields.read(in, MAX_PRIVATE_KEY_BYTES);
            encryptionKeyBytes = Fields.read(in, MAX_PRIVATE_KEY_BYTES);

            if (in.read() != -1) {
                throw new IOException("Unexpected bytes after identity contents");
            }

            signingPrivate = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(signingKeyBytes));
            encryptionPrivate = KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(encryptionKeyBytes));
        } finally {
            // Best-effort wiping. Java may keep other copies in memory.
            Arrays.fill(plaintext, (byte) 0);
            if (signingKeyBytes != null) {
                Arrays.fill(signingKeyBytes, (byte) 0);
            }
            if (encryptionKeyBytes != null) {
                Arrays.fill(encryptionKeyBytes, (byte) 0);
            }
        }

        // The credential must be signed by the relay this client trusts.
        Credential credential = CredentialCodec.verify(credentialBytes, trustedRelayKey);
        String certifiedIdentity = credential.registration().identity();

        if (!certifiedIdentity.equals(storedIdentity)
                || !storedIdentity.equals(expectedIdentity)) {
            throw new IOException("Identity file belongs to a different identity");
        }

        PublicKey signingPublic = credential.registration().signingPublicKey();
        PublicKey encryptionPublic = credential.registration().encryptionPublicKey();
        requireMatchingKeys(signingPrivate, signingPublic,
                encryptionPrivate, encryptionPublic);

        return new ClientIdentity(storedIdentity, credentialBytes,
                new KeyPair(signingPublic, signingPrivate),
                new KeyPair(encryptionPublic, encryptionPrivate));
    }

    /**
     * Encodes the 37-byte cleartext header.
     */
    private static byte[] encodeHeader(int iterations, byte[] salt, byte[] nonce)
            throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(MAGIC);
            out.writeByte(VERSION);
            out.writeInt(iterations);
            out.write(salt);
            out.write(nonce);
        }

        return buffer.toByteArray();
    }

    /**
     * Encodes the identity, credential and both private keys.
     */
    private static byte[] encodePlaintext(ClientIdentity identity) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            // encodeRequest also validates the identity characters.
            Fields.write(out, DiscoveryCodec.encodeRequest(identity.identity()),
                    RegistrationCodec.MAX_IDENTITY_BYTES);
            Fields.write(out, identity.credential(),
                    CredentialCodec.MAX_PAYLOAD_BYTES);

            // getEncoded() returns the PKCS#8 encoding of a private key.
            Fields.write(out, identity.signingKeys().getPrivate().getEncoded(),
                    MAX_PRIVATE_KEY_BYTES);
            Fields.write(out, identity.encryptionKeys().getPrivate().getEncoded(),
                    MAX_PRIVATE_KEY_BYTES);
        }

        return buffer.toByteArray();
    }

    /**
     * Derives the AES-256 file key and wipes the raw derived bytes.
     */
    private static SecretKey deriveKey(char[] password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        byte[] keyBytes = PasswordEncryption.deriveKeyBytes(
                password, salt, iterations, PasswordEncryption.KEY_BYTES);

        try {
            // SecretKeySpec keeps its own copy of the bytes.
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Requires each private key to belong to the public key in the credential.
     */
    private static void requireMatchingKeys(PrivateKey signingPrivate,
                                            PublicKey signingPublic,
                                            PrivateKey encryptionPrivate,
                                            PublicKey encryptionPublic)
            throws IOException, GeneralSecurityException {
        // The JDK cannot derive an Ed25519 public key, so sign a random probe.
        byte[] probe = new byte[32];
        RANDOM.nextBytes(probe);

        byte[] signature = Signatures.sign(probe, signingPrivate);
        if (!Signatures.verify(probe, signature, signingPublic)) {
            throw new IOException("Signing key does not match the credential");
        }

        // An RSA key pair shares its modulus and public exponent.
        if (!(encryptionPrivate instanceof RSAPrivateCrtKey rsaPrivate)
                || !(encryptionPublic instanceof RSAPublicKey rsaPublic)
                || !rsaPrivate.getModulus().equals(rsaPublic.getModulus())
                || !rsaPrivate.getPublicExponent().equals(rsaPublic.getPublicExponent())) {
            throw new IOException("Encryption key does not match the credential");
        }
    }
}