package io.github.rfc3507.server;

import com.github.pfmiles.icapserver.impl.Constants;
import com.github.pfmiles.icapserver.impl.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class Worker {

    private static final Logger logger = LoggerFactory.getLogger(Worker.class);
    private static final AtomicLong seq = new AtomicLong();

    private static final ExecutorService reqHandlePool = new ThreadPoolExecutor(1, Constants.INSTANCE.getWORKER_POOL_SIZE(),
            60L, TimeUnit.SECONDS,
            new SynchronousQueue<>(),
            r -> new Thread(r, "icap-server-worker-thread-" + seq.getAndIncrement()));

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
                reqHandlePool.shutdown();
                if (reqHandlePool.awaitTermination(5, TimeUnit.SECONDS)) {
                    // terminates smoothly
                    logger.info("All adaptation requests handling finished.");
                } else {
                    reqHandlePool.shutdownNow();
                    logger.warn("Some of the adaptation jobs are still running, stopped forcibly.");
                }
            } catch (IOException e) {
                logger.error("Error when closing the server socket.", e);
            } catch (InterruptedException e) {
                logger.error("Shutdown waiting of request handling pool is interrupted, ignored...", e);
            }
            logger.info("[ICAP-SERVER] Service terminated.");
        }, "icap-server-shutdown-hook");
        Runtime.getRuntime().addShutdownHook(shutdown);

        Executors.newSingleThreadExecutor(r -> new Thread(r, "icap-server-main-thread")).submit(this::startService);
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
        final String servicePort = Utils.INSTANCE.optsInOrDefault(Constants.PORT_ENV_VAR, Constants.PORT_PROP_VAR, Constants.DFT_PORT);

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

            CompletableFuture.runAsync(new ClientHandler(client), reqHandlePool);
        }
    }

}
