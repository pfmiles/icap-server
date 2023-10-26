package io.github.rfc3507.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;

public class Worker {

    private static final Logger logger = LoggerFactory.getLogger(Worker.class);

    public static void main(String[] args) {
        new Worker().start();
    }

    private ServerSocket serverSocket;

    public void start() {
        final Thread shutdown = new Thread(() -> {
            try {
                if (!serverSocket.isClosed()) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                logger.error("Error when closing the server socket.", e);
            }
            logger.info("[ICAP-SERVER] Service terminated.");
        });
        Runtime.getRuntime().addShutdownHook(shutdown);

        Executors.newSingleThreadExecutor().submit(this::startService);
    }

    public void stop() {
        try {
            serverSocket.close();
        } catch (IOException e) {
            logger.error("Error when stopping the service, ignored.", e);
        }
    }

    private void startService() {
        try {
            listen();
        } catch (IOException e) {
            logger.error("Exception thrown while opening server socket, service will shutdown.", e);
            stop();
        }
    }

    private void listen() throws IOException {
        // icap server port could be specified by OS environment variable 'ICAP_SERVER_PORT' or 'icap.server.port' system property, or else 1344 by default
        final String servicePort = Optional
                .ofNullable(System.getenv("ICAP_SERVER_PORT"))
                .orElse(Optional
                        .ofNullable(System.getProperty("icap.server.port"))
                        .orElse("1344"));

        this.serverSocket = new ServerSocket(Integer.parseInt(servicePort));

        logger.info("[ICAP-SERVER] Listening on port " + servicePort);

        while (true) {
            Socket client;
            try {
                client = serverSocket.accept();
                logger.info("[ICAP-SERVER] Connection received!");
            } catch (SocketException e) {
                logger.info("Server socket closed, program will exit.");
                break;
            } catch (IOException e) {
                logger.error("Error when accepting incoming connection, ignored...", e);
                continue;
            }

            CompletableFuture.runAsync(new ClientHandler(client));
        }

    }

}
