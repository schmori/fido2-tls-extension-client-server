package tls.utility;

import tls.sockets.client.CTAP2;
import tls.sockets.client.CTAP2Database;
import tls.sockets.client.TLSClient;
import tls.sockets.server.FIDODatabase;
import tls.sockets.server.FIDOServer;
import tls.sockets.server.TLSServer;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static java.lang.Thread.sleep;

public class StartAllSockets {
    public static void main(String[] args) throws InterruptedException {
        thread1.start();
        thread2.start();
        thread3.start();
        thread4.start();
    }

    static Thread thread1 = new Thread(() -> {
        try {
            CTAP2.startCTAP2();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    });

    static Thread thread2 = new Thread(() -> {
        try {
            FIDOServer.startFIDOServer();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    });

    static Thread thread3 = new Thread(() -> {
        try {
            TLSServer.startTLSServer();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    });

    static Thread thread4 = new Thread(() -> {
        try {
            TLSClient.startTLSClient();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    });
}
