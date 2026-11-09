package pt.ua.si.quackchat.relay;

import pt.ua.si.quackchat.shared.protocol.ProtocolConfig;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.PrivateKey;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * RelayServer
 * Accepts clients continuously and processes a bounded number of sessions concurrently.
 */
public final class RelayServer implements AutoCloseable {
    private final ServerSocket listener;
    private final ThreadPoolExecutor workers;

    // Shared relay identity used to sign client credentials.
    private final PrivateKey relaySigningKey;

    // Share registered credentials across all sessions handled by this relay.
    private final ClientDirectory directory = new ClientDirectory();

    public RelayServer(int port, PrivateKey relaySigningKey) throws IOException {
        this.relaySigningKey =
                Objects.requireNonNull(relaySigningKey, "relaySigningKey");

        listener = new ServerSocket(port);  //  Socket created to listen Server | Wait for new connections
        workers = new ThreadPoolExecutor(
                ProtocolConfig.MAX_CLIENT_WORKERS,  // ProtocolConfig.java import (8)
                ProtocolConfig.MAX_CLIENT_WORKERS,  // ProtocolConfig.java import (8)
                0L,     //  0 milliseconds - inactive thread period                                 
                TimeUnit.MILLISECONDS,  //  Keeps 0L in milliseconds
                new ArrayBlockingQueue<>(ProtocolConfig.MAX_QUEUED_CLIENTS),    //  FIFO queue control
                new ThreadPoolExecutor.AbortPolicy()    //  Abort when all workers busy
        );
    }

/**
 * 
 * @return Port
 */
    public int port() {
        return listener.getLocalPort(); //  gets the Port `listener` is using
    }

    /*  Establishes Connection with Client */
    /**
     * 
     * @throws IOException
     */

    public void serve() throws IOException {
        try {
            while (!listener.isClosed()) {
                Socket client = listener.accept();  //  It runs when client establishes connection
                dispatch(client);
            }
        } catch (SocketException e) {
            if (!listener.isClosed()) {
                throw e;
            }
        } finally {
            workers.shutdown(); //  if `dispatch(Socket client)` throws RunTimeException
        }
    }

    /*  Workers Func */
    /**
    * When thread pool, and it's queue are full, AbortPolicy runs RejectedExecutionException
    * @param client
    */
    private void dispatch(Socket client) {
        try {
            workers.execute(() -> handle(client));  //  When worker is avaiable, `execute()` calls `handle(client)`
        } catch (RejectedExecutionException e) {
            System.err.println("[!] Relay is at capacity; rejecting " + client.getRemoteSocketAddress());
            try {
                client.close();
            } catch (IOException closeFailure) {
                System.err.println("[!] Could not close rejected client: " + closeFailure.getMessage());
            }
        }
    }

    /**
     * Every Client Socket might be accepted
     * @param client
     */
    private void handle(Socket client) {
        try (Socket connection = client) {
            System.out.println("[*] Client connected: " + connection.getRemoteSocketAddress());
            RelaySession.handle(connection, relaySigningKey, directory);
        } catch (IOException e) {
            System.err.println("[!] Client session failed: " + e);
        }
    }
/**
 * 
 * @see java.lang.AutoCloseable#close()
 */
    @Override
    public void close() throws IOException {
        listener.close();
        workers.shutdown();
    }
}
