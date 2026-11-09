package pt.ua.si.quackchat.shared.protocol;

import pt.ua.si.quackchat.shared.crypto.KeyEnvelopes;
import pt.ua.si.quackchat.shared.crypto.MessageEncryption;
import pt.ua.si.quackchat.shared.crypto.Signatures;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.UUID;

public final class MessageCodec {
    // Identify the signed message format and version.
    private static final byte[] CONTEXT =
            "QuackChat:message:v1".getBytes(StandardCharsets.UTF_8);

    // Bound message content and the final Ed25519 signature.
    // 4,096-byte plaintext limit is the bounded demo-message size, not a cryptographic limit.
    public static final int MAX_PLAINTEXT_BYTES = 4_096;
    private static final int SIGNATURE_BYTES = 64;

    // Maximum complete envelope size, including:
    //   Fixed protocol context and a 16-byte UUID.
    //   Two identities, each with a 4-byte length prefix.
    //   The sender credential, with its 4-byte length prefix.
    //   The fixed-size GCM nonce and RSA-wrapped AES key.
    //   Ciphertext, with its 4-byte length prefix and appended GCM tag.
    //   The final 64-byte Ed25519 signature.
    // Variable fields use their maximum permitted sizes in this calculation.
    private static final int MAX_PAYLOAD_BYTES =
            CONTEXT.length
                    + 2 * Long.BYTES
                    + 2 * (Integer.BYTES + RegistrationCodec.MAX_IDENTITY_BYTES)
                    + Integer.BYTES + CredentialCodec.MAX_PAYLOAD_BYTES
                    + MessageEncryption.NONCE_BYTES
                    + KeyEnvelopes.WRAPPED_KEY_BYTES
                    + Integer.BYTES + MAX_PLAINTEXT_BYTES
                    + MessageEncryption.TAG_BYTES
                    + SIGNATURE_BYTES;

    public record Header(UUID messageId, String sender, String recipient) {}

    public record OpenedMessage(Header header, byte[] plaintext) {}

    private MessageCodec() {}

    /**
     * Encrypts and signs a message for a recipient.
     *
     * @param sender the registered sender identity
     * @param recipient the intended recipient identity
     * @param plaintext the message content
     * @param senderCredential the sender's original signed credential payload
     * @param signingKey the sender's Ed25519 private key
     * @param recipientKey the RSA public key from the verified recipient credential
     * @return the complete protected message payload
     * @throws IOException if encoding or field validation fails
     * @throws GeneralSecurityException if a cryptographic operation fails
     */
    public static byte[] protect(
            String sender, String recipient, byte[] plaintext,
            byte[] senderCredential, PrivateKey signingKey,
            PublicKey recipientKey)
            throws IOException, GeneralSecurityException {
        if (plaintext == null || plaintext.length > MAX_PLAINTEXT_BYTES) {
            throw new IOException("Invalid message content length");
        }

        if (senderCredential == null || senderCredential.length == 0
                || senderCredential.length > CredentialCodec.MAX_PAYLOAD_BYTES) {
            throw new IOException("Invalid sender credential length");
        }

        // Assign an identifier and encode the metadata authenticated by GCM.
        Header header = new Header(UUID.randomUUID(), sender, recipient);
        byte[] headerBytes = encodeHeader(header);

        // Generate independent encryption material for this message.
        SecretKey messageKey = MessageEncryption.generateKey();
        byte[] nonce = MessageEncryption.generateNonce();
        byte[] ciphertext = MessageEncryption.encrypt(
                plaintext, messageKey, nonce, headerBytes);
        byte[] wrappedKey = KeyEnvelopes.wrap(messageKey, recipientKey);

        // This message format uses RSA-3072 key envelopes.
        if (wrappedKey.length != KeyEnvelopes.WRAPPED_KEY_BYTES) {
            throw new IOException("Expected an RSA-3072 key envelope");
        }

        // Assemble the envelope fields in the exact order expected by open().
        // Variable-size fields carry length prefixes, fixed-size fields do not.
        // These bytes will all be covered by the sender's signature.
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(headerBytes);
            writeField(out, senderCredential);
            out.write(nonce);
            out.write(wrappedKey);
            writeField(out, ciphertext);
        }

        // Sign the complete encoded envelope before appending its signature.
        byte[] signedData = buffer.toByteArray();
        byte[] signature = Signatures.sign(signedData, signingKey);

        if (signature.length != SIGNATURE_BYTES) {
            throw new IOException("Unexpected message signature length");
        }

        byte[] payload = Arrays.copyOf(
                signedData, signedData.length + signature.length);
        System.arraycopy(signature, 0, payload,
                signedData.length, signature.length);

        return payload;
    }

    /**
     * Reads routing metadata without authenticating the message.
     *
     * @param payload the complete protected message
     * @return the unverified header
     * @throws IOException if the payload or header is malformed
     */
    public static Header readHeader(byte[] payload) throws IOException {
        validatePayloadLength(payload);

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(payload))) {
            return readHeader(in);
        }
    }

    /**
     * Verifies and decrypts a message addressed to this recipient.
     *
     * @param payload the original received message payload
     * @param expectedRecipient this client's registered identity
     * @param recipientKey this client's RSA private key
     * @param trustedRelayKey the previously trusted relay public key
     * @return the authenticated header and decrypted content
     * @throws IOException if the format, identities or signatures are invalid
     * @throws GeneralSecurityException if verification or decryption fails
     */
    public static OpenedMessage open(byte[] payload,
                                     String expectedRecipient,
                                     PrivateKey recipientKey,
                                     PublicKey trustedRelayKey)
            throws IOException, GeneralSecurityException {
        validatePayloadLength(payload);

        // Preserve the exact received bytes covered by the signature.
        int signatureOffset = payload.length - SIGNATURE_BYTES;
        byte[] signedData = Arrays.copyOfRange(payload, 0, signatureOffset);
        byte[] signature = Arrays.copyOfRange(
                payload, signatureOffset, payload.length);

        try (DataInputStream in = new DataInputStream(
                new ByteArrayInputStream(signedData))) {
            Header header = readHeader(in);

            // This is an in-memory stream: available() is the remaining byte count.
            int headerLength = signedData.length - in.available();
            byte[] headerBytes = Arrays.copyOf(signedData, headerLength);

            if (!expectedRecipient.equals(header.recipient())) {
                throw new IOException("Message addressed to a different recipient");
            }

            // Parse bounded fields before using their contents.
            byte[] senderCredential = readField(
                    in, CredentialCodec.MAX_PAYLOAD_BYTES);

            // Read the fixed 12-byte nonce used to initialize AES-GCM.
            byte[] nonce = new byte[MessageEncryption.NONCE_BYTES];
            in.readFully(nonce);

            // Read the fixed 384-byte RSA-3072 envelope containing the encrypted AES key.
            byte[] wrappedKey = new byte[KeyEnvelopes.WRAPPED_KEY_BYTES];
            in.readFully(wrappedKey);

            // Read the length-prefixed ciphertext, including its appended GCM tag.
            byte[] ciphertext = readField(
                    in, MAX_PLAINTEXT_BYTES + MessageEncryption.TAG_BYTES);

            if (ciphertext.length < MessageEncryption.TAG_BYTES) {
                throw new IOException("Message is missing its GCM tag");
            }

            if (in.read() != -1) {
                throw new IOException("Unexpected bytes after message content");
            }

            // Establish the sender's signing key through the trusted relay.
            Credential credential =
                    CredentialCodec.verify(senderCredential, trustedRelayKey);

            if (!header.sender().equals(credential.registration().identity())) {
                throw new IOException("Sender does not match its credential");
            }

            // Authenticate the complete original envelope before decrypting.
            if (!Signatures.verify(
                    signedData, signature,
                    credential.registration().signingPublicKey())) {
                throw new IOException("Invalid message signature");
            }

            SecretKey messageKey = KeyEnvelopes.unwrap(wrappedKey, recipientKey);

            // GCM verifies both the encrypted content and the original header bytes.
            byte[] plaintext = MessageEncryption.decrypt(
                    ciphertext, messageKey, nonce, headerBytes);

            return new OpenedMessage(header, plaintext);
        }
    }

    /**
     * Encodes the fixed context, message ID and bounded identities.
     */
    private static byte[] encodeHeader(Header header) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        try (DataOutputStream out = new DataOutputStream(buffer)) {
            out.write(CONTEXT);

            // A UUID occupies two longs: 16 bytes in total.
            out.writeLong(header.messageId().getMostSignificantBits());
            out.writeLong(header.messageId().getLeastSignificantBits());

            // Reuse the identity rules already enforced by discovery.
            writeField(out, DiscoveryCodec.encodeRequest(header.sender()));
            writeField(out, DiscoveryCodec.encodeRequest(header.recipient()));
        }

        return buffer.toByteArray();
    }

    /**
     * Reads and validates the header structure without verifying a signature.
     */
    private static Header readHeader(DataInputStream in) throws IOException {
        byte[] context = new byte[CONTEXT.length];
        in.readFully(context);

        if (!Arrays.equals(context, CONTEXT)) {
            throw new IOException("Unexpected message context");
        }

        UUID messageId = new UUID(in.readLong(), in.readLong());

        String sender = DiscoveryCodec.decodeRequest(
                readField(in, RegistrationCodec.MAX_IDENTITY_BYTES));
        String recipient = DiscoveryCodec.decodeRequest(
                readField(in, RegistrationCodec.MAX_IDENTITY_BYTES));

        return new Header(messageId, sender, recipient);
    }

    /**
     * Writes a field preceded by its byte length.
     */
    private static void writeField(DataOutputStream out, byte[] value)
            throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    /**
     * Reads a bounded field, validating its length before allocation.
     */
    private static byte[] readField(DataInputStream in, int maximum)
            throws IOException {
        int length = in.readInt();
        if (length <= 0 || length > maximum) {
            throw new IOException("Invalid message field length");
        }

        byte[] value = new byte[length];
        in.readFully(value);
        return value;
    }

    /**
     * Rejects oversized payloads and payloads without room for signed data.
     */
    private static void validatePayloadLength(byte[] payload) throws IOException {
        if (payload == null || payload.length <= SIGNATURE_BYTES
                || payload.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("Invalid protected message length");
        }
    }
}