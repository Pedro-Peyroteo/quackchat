package pt.ua.si.quackchat.shared.protocol;

import java.security.SecureRandom;

/** Protocol Configuration */
public final class ProtocolConfig {
    public static final String DEFAULT_RELAY_HOST = "localhost";
    public static final int DEFAULT_RELAY_PORT = 5000;

    public static final int CONNECT_TIMEOUT_MILLIS = 5_000; //  limit to establish relay-client connection (5s)
    public static final int READ_TIMEOUT_MILLIS = 5_000;    //  limit of waiting for received data within an open connection (5s)
    public static final int MAX_CLIENT_WORKERS = 8;         //  limit of 8 client sections in relay
    public static final int MAX_QUEUED_CLIENTS = 64;        //  limit of 64 connections waiting for a worker

    // Number of random bytes in a registration challenge.
    public static final int REGISTRATION_CHALLENGE_BYTES = 32;

    private ProtocolConfig() {}
}
