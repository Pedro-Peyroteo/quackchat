package pt.ua.si.quackchat.shared.protocol;

/** Timeouts Configuration */
public final class ProtocolConfig {
    public static final int CONNECT_TIMEOUT_MILLIS = 5_000; //  limit to establish relay-client connection
    public static final int READ_TIMEOUT_MILLIS = 5_000;    //  limit of waiting for received data within an open connection 

    private ProtocolConfig() {}
}
