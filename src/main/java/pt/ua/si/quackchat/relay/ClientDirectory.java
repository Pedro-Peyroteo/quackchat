package pt.ua.si.quackchat.relay;

import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Stores registered identities and their signed credentials for this relay run.
 */
public final class ClientDirectory {
    /**
     * A registered identity: the credential returned by discovery, and the
     * signing key that login proofs are checked against.
     */
    private record Entry(byte[] credential, PublicKey signingKey) {}

    private final ConcurrentMap<String, Entry> entries =
            new ConcurrentHashMap<>();

    // Track active connections separately from stored credentials.
    private final ConcurrentMap<String, ClientConnection> online =
            new ConcurrentHashMap<>();

    /**
     * Stores a credential only if the identity is not already registered.
     *
     * @param identity the identity whose registration proof was verified
     * @param credentialPayload the relay-signed credential bytes
     * @param signingKey the Ed25519 key certified in that credential
     * @return true if inserted, or false if the identity already exists
     */
    public boolean register(String identity, byte[] credentialPayload,
                            PublicKey signingKey) {
        // Copy the array so callers cannot modify the stored credential.
        Entry entry = new Entry(credentialPayload.clone(), signingKey);

        // Atomically check and insert, even when sessions register concurrently.
        return entries.putIfAbsent(identity, entry) == null;
    }

    /**
     * Finds the signed credential associated with an identity.
     *
     * @param identity the identity to find
     * @return a copy of the credential, or null if no entry exists
     */
    public byte[] find(String identity) {
        Entry entry = entries.get(identity);

        // Keep the directory's internal array private.
        return entry == null ? null : entry.credential().clone();
    }

    /**
     * Finds the signing key stored at registration, for verifying logins.
     *
     * @param identity the identity to find
     * @return the registered Ed25519 public key, or null if unknown
     */
    public PublicKey findSigningKey(String identity) {
        Entry entry = entries.get(identity);
        return entry == null ? null : entry.signingKey();
    }

    /**
     * Associates an authenticated identity with its live connection.
     *
     * @return the connection this one replaces, or null if there was none
     */
    public ClientConnection markOnline(String identity, ClientConnection connection) {
        return online.put(identity, connection);
    }

    /**
     * Finds an active connection, or returns null if the client is offline.
     */
    public ClientConnection findOnline(String identity) {
        return online.get(identity);
    }

    /**
     * Removes this connection without deleting the registered credential.
     *
     * @return true if this connection was the identity's online connection
     */
    public boolean markOffline(String identity, ClientConnection connection) {
        // Remove only if this exact connection is still associated with the identity.
        return online.remove(identity, connection);
    }
}
