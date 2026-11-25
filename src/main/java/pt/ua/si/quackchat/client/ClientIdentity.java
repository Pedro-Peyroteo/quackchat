package pt.ua.si.quackchat.client;

import java.security.KeyPair;

/**
 * A client's registered identity: its name, the relay-signed credential
 * and both key pairs.
 *
 * The public keys always come from the credential, so they are exactly
 * the keys the relay certified.
 *
 * @param identity the registered identity
 * @param credential the original relay-signed credential bytes
 * @param signingKeys the Ed25519 key pair
 * @param encryptionKeys the RSA key pair
 */
public record ClientIdentity(String identity, byte[] credential,
                             KeyPair signingKeys, KeyPair encryptionKeys) {}