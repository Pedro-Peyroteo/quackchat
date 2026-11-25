package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.crypto.KeyEnvelopes;
import pt.ua.si.quackchat.shared.crypto.MessageEncryption;
import pt.ua.si.quackchat.shared.crypto.Signatures;
import pt.ua.si.quackchat.shared.protocol.CredentialCodec;
import pt.ua.si.quackchat.shared.protocol.RegisterRequest;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.Stream;

public class IdentityStoreCheck {
    // Offsets inside a saved file: magic at 0, salt at 9, contents from 37.
    private static final int SALT_OFFSET = 9;
    private static final int CIPHERTEXT_OFFSET = 40;

    /** An action expected to fail with an IOException or a security exception. */
    private interface Attempt {
        void run() throws IOException, GeneralSecurityException;
    }

    /**
     * Displays the result of each identity file check.
     *
     * @param args unused command-line arguments
     * @throws Exception if a check fails unexpectedly
     */
    public static void main(String[] args) throws Exception {
        char[] password = "correct horse battery staple".toCharArray();
        char[] wrongPassword = "correct horse battery stapler".toCharArray();

        // A relay and Alice's keys, as after a real registration.
        KeyPair relay = Signatures.generateKeyPair();
        KeyPair otherRelay = Signatures.generateKeyPair();
        KeyPair signing = Signatures.generateKeyPair();
        KeyPair encryption = KeyEnvelopes.generateKeyPair();

        byte[] credential = CredentialCodec.issue(
                new RegisterRequest("alice", signing.getPublic(), encryption.getPublic()),
                relay.getPrivate());
        ClientIdentity alice = new ClientIdentity("alice", credential, signing, encryption);

        // Work in a temporary directory so the real clients/ is never touched.
        Path directory = Files.createTempDirectory("quackchat-check");
        Path file = directory.resolve("alice").resolve("identity.bin");

        try {
            IdentityStore.save(file, alice, password);
            byte[] saved = Files.readAllBytes(file);
            System.out.println("Saved identity file = " + saved.length + " bytes");

            // Should: Load, then confirm the keys still work.
            ClientIdentity loaded = IdentityStore.load(
                    file, "alice", password, relay.getPublic());

            // Should: The identity and credential bytes come back unchanged.
            boolean sameContents = loaded.identity().equals("alice")
                    && Arrays.equals(loaded.credential(), credential);

            // Should: The loaded signing key makes signatures the original public key accepts.
            byte[] probe = "probe".getBytes(StandardCharsets.UTF_8);
            boolean signingWorks = Signatures.verify(probe,
                    Signatures.sign(probe, loaded.signingKeys().getPrivate()),
                    signing.getPublic());

            // Should: The loaded RSA key unwraps a message key wrapped for the original public key.
            SecretKey messageKey = MessageEncryption.generateKey();
            SecretKey unwrapped = KeyEnvelopes.unwrap(
                    KeyEnvelopes.wrap(messageKey, encryption.getPublic()),
                    loaded.encryptionKeys().getPrivate());
            boolean encryptionWorks = Arrays.equals(
                    messageKey.getEncoded(), unwrapped.getEncoded());

            // Should: Save and load lose nothing.
            boolean roundTrip = sameContents && signingWorks && encryptionWorks;
            System.out.println("Save and load round trip = " + roundTrip);

            // Should: A near-miss password derives a different key, so GCM fails.
            boolean wrongPasswordRejected =rejects(() -> IdentityStore.load(
                    file, "alice", wrongPassword, relay.getPublic()));
            System.out.println("Wrong password rejected = " + wrongPasswordRejected);

            // Should: A file that is not ours is refused before any decryption.
            boolean magicRejected =rejects(() -> loadTampered(
                    directory, saved, 0, password, relay.getPublic()));
            System.out.println("Changed magic rejected = " + magicRejected);

            // Should: A changed salt derives a different key, so GCM fails.
            boolean saltRejected =rejects(() -> loadTampered(
                    directory, saved, SALT_OFFSET, password, relay.getPublic()));
            System.out.println("Changed salt rejected = " + saltRejected);

            // Should: One flipped bit in the encrypted part fails the GCM tag.
            boolean ciphertextRejected =rejects(() -> loadTampered(
                    directory, saved, CIPHERTEXT_OFFSET, password, relay.getPublic()));
            System.out.println("Changed ciphertext rejected = " + ciphertextRejected);

            // Should: A cut-off file loses part of its tag, so GCM fails.
            boolean truncatedRejected =rejects(() -> loadBytes(directory,
                    Arrays.copyOf(saved, saved.length - 1), password, relay.getPublic()));
            System.out.println("Truncated file rejected = " + truncatedRejected);

            // Should: Alice's file cannot be used to start as bob.
            boolean wrongIdentityRejected =rejects(() -> IdentityStore.load(
                    file, "bob", password, relay.getPublic()));
            System.out.println("Loading as bob rejected = " + wrongIdentityRejected);

            // Should: A credential not signed by the trusted relay is refused.
            boolean wrongRelayRejected =rejects(() -> IdentityStore.load(
                    file, "alice", password, otherRelay.getPublic()));
            System.out.println("Credential from another relay rejected = " + wrongRelayRejected);

            // Should: The only copy of the keys is never overwritten (D11).
            boolean overwriteRefused =rejects(() -> IdentityStore.save(file, alice, password));
            System.out.println("Overwrite refused = " + overwriteRefused);

            // Should: An identity cannot point the file outside clients/ (D11).
            boolean traversalRejected =rejects(() -> IdentityStore.pathFor("../keys"));
            System.out.println("Path traversal identity rejected = " + traversalRejected);

            // Should: Fail the check if any result differs from the expected.
            if (!roundTrip || !wrongPasswordRejected || !magicRejected
                    || !saltRejected || !ciphertextRejected || !truncatedRejected
                    || !wrongIdentityRejected || !wrongRelayRejected
                    || !overwriteRefused || !traversalRejected) {
                throw new GeneralSecurityException("Unexpected identity store result.");
            }

            System.out.println("All identity store checks passed");
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(wrongPassword, '\0');
            deleteRecursively(directory);
        }
    }

    /**
     * Returns true only if the attempt fails with an expected exception.
     */
    private static boolean rejects(Attempt attempt) {
        try {
            attempt.run();
            return false;
        } catch (IOException | GeneralSecurityException e) {
            System.out.println("  (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
            return true;
        }
    }

    /**
     * Flips one bit of a copy of the saved file and loads the copy.
     */
    private static void loadTampered(Path directory, byte[] saved, int offset,
                                     char[] password, PublicKey relayKey)
            throws IOException, GeneralSecurityException {
        byte[] changed = saved.clone();
        changed[offset] ^= 1;
        loadBytes(directory, changed, password, relayKey);
    }

    /**
     * Writes the bytes to a new file and loads it as alice.
     */
    private static void loadBytes(Path directory, byte[] bytes,
                                  char[] password, PublicKey relayKey)
            throws IOException, GeneralSecurityException {
        Path copy = Files.createTempFile(directory, "tampered", ".bin");
        Files.write(copy, bytes);
        IdentityStore.load(copy, "alice", password, relayKey);
    }

    /**
     * Deletes the temporary directory and everything in it.
     */
    private static void deleteRecursively(Path directory) throws IOException {
        try (Stream<Path> paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }
}