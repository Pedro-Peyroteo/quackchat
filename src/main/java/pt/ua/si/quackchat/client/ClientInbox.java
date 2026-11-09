package pt.ua.si.quackchat.client;

import pt.ua.si.quackchat.shared.protocol.Frame;
import pt.ua.si.quackchat.shared.protocol.FrameCodec;
import pt.ua.si.quackchat.shared.protocol.MessageCodec;
import pt.ua.si.quackchat.shared.protocol.MessageType;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Processes deliveries through the client's single connection-reading thread.
 */
public class ClientInbox {
    private final String identity;
    private final PrivateKey encryptionKey;
    private final PublicKey trustedRelayKey;

    // Remember accepted messages for the lifetime of this client process.
    private final Set<MessageId> received = new HashSet<>();

    private record MessageId(String sender, UUID value) {}

    public ClientInbox(String identity, PrivateKey encryptionKey,
                       PublicKey trustedRelayKey) {
        this.identity = identity;
        this.encryptionKey = encryptionKey;
        this.trustedRelayKey = trustedRelayKey;
    }

    /**
     * Handles deliveries while waiting for the next non-delivery response.
     *
     * @param in this connection's sole input stream
     * @return the next control response, such as discovery or an error
     * @throws java.io.IOException if reading fails
     */
    public Frame readResponse(DataInputStream in) throws IOException {
        while (true) {
            Frame frame = FrameCodec.read(in);

            if (frame.type() == MessageType.DELIVER_MESSAGE) {
                displayMessage(frame.payload());
            } else {
                return frame;
            }
        }
    }

    /**
     * Waits for deliveries and relay errors until the connection closes.
     *
     * @param in this connection's sole input stream
     * @throws IOException if reading fails or an unexpected response arrives
     */
    public void listen(DataInputStream in) throws IOException {
        try {
            while (true) {
                // Deliveries are processed inside readResponse().
                Frame response = readResponse(in);

                if (response.type() == MessageType.ERROR) {
                    System.err.println("[!] Relay error: "
                            + new String(response.payload(), StandardCharsets.UTF_8));
                } else {
                    throw new IOException(
                            "Unexpected response while listening: " + response.type());
                }
            }
        } catch (EOFException e) {
            System.out.println("[*] Relay closed the connection");
        }
    }

    /**
     * Displays content only after cryptographic checks and duplicate detection.
     */
    private void displayMessage(byte[] payload) {
        try {
            MessageCodec.OpenedMessage message = MessageCodec.open(
                    payload, identity, encryptionKey, trustedRelayKey);

            MessageId id = new MessageId(
                    message.header().sender(), message.header().messageId());

            // Record IDs only after the message has passed authentication.
            if (!received.add(id)) {
                throw new IOException("Duplicate message");
            }

            System.out.println("[*] Verified message "
                    + message.header().messageId()
                    + " from " + message.header().sender());

            System.out.println(message.header().sender() + ": "
                    + new String(message.plaintext(), StandardCharsets.UTF_8));
        } catch (IOException | GeneralSecurityException e) {
            // Reject this message without displaying its content.
            System.err.println("[!] Rejected message: " + e.getMessage());
        }
    }


}
