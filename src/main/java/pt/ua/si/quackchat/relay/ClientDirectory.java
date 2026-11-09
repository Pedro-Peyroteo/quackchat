package pt.ua.si.quackchat.relay;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Stores registered identities and their signed credentials for this relay run.
 */
public final class ClientDirectory {
    private final ConcurrentMap<String, byte[]> credentials =
            new ConcurrentHashMap<>();

    // Track active connections separately from stored credentials.
    private final ConcurrentMap<String, ClientConnection> online =
            new ConcurrentHashMap<>();

    /**
     * Stores a credential only if the identity is not already registered.
     *
     * @param identity the identity whose registration proof was verified
     * @param credentialPayload the relay-signed credential bytes
     * @return true if inserted, or false if the identity already exists
     */
    public boolean register(String identity, byte[] credentialPayload) {
        // Copy the array so callers cannot modify the stored credential.
        byte[] storedCopy = credentialPayload.clone();

        // Atomically check and insert, even when sessions register concurrently.
        return credentials.putIfAbsent(identity, storedCopy) == null;
    }

    /**
     * Finds the signed credential associated with an identity.
     *
     * @param identity the identity to find
     * @return a copy of the credential, or null if no entry exists
     */
    public byte[] find(String identity) {
        byte[] credentialPayload = credentials.get(identity);

        // Keep the directory's internal array private.
        return credentialPayload == null ? null : credentialPayload.clone();
    }

    /**
     * Associates a successfully registered identity with its live connection.
     */
    public void markOnline(String identity, ClientConnection connection) {
        online.put(identity, connection);
    }

    /**
     * Finds an active connection, or returns null if the client is offline.
     */
    public ClientConnection findOnline(String identity) {
        return online.get(identity);
    }

    /**
     * Removes this connection without deleting the registered credential.
     */
    public void markOffline(String identity, ClientConnection connection) {
        // Remove only if this exact connection is still associated with the identity.
        online.remove(identity, connection);
    }
}
