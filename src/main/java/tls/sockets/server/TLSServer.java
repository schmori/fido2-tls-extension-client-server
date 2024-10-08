package tls.sockets.server;

import tls.utility.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;

/*
 * optional VM options: -Djavax.net.debug=ssl:handshake
 * */

public class TLSServer {

    public static void main(String[] args) {
        try {
            startTLSServer();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static void setAuthenticationScheme() {
        String systemPath = System.getProperty("user.dir");
        String sep = System.getProperty("file.separator");

        System.setProperty("javax.net.ssl.keyStore", systemPath+sep+"src"+sep+"main"+sep+"resources"+sep+"serverkeystore.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.trustStore", systemPath+sep+"src"+sep+"main"+sep+"resources"+sep+"servertruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
    }

    public static void startTLSServer() throws IOException, GeneralSecurityException {
        setAuthenticationScheme();

        SSLParameters params = new SSLParameters();
        params.setNeedClientAuth(true);
        params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        params.setProtocols(new String[]{"TLSv1.3"});

        params.setRpID(VARIABLES.RPID);
        params.setTicket(VARIABLES.TICKET.getBytes());
        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(VARIABLES.TLS_PORT)) {
            listener.setSSLParameters(params);
            Logger.log("TLS Server started");
            while (true) {
                try (Socket clientSocket = listener.accept()) {
                    Logger.log("TLS Server: Accepted " + clientSocket);

                    InputStream is = new BufferedInputStream(clientSocket.getInputStream());
                    byte[] data = new byte[2048];
                    int len = is.read(data);

                    String message = new String(data, 0, len);
                    Logger.log("TLS Server: Received message by TLS Client: " + message);

                    OutputStream os = new BufferedOutputStream(clientSocket.getOutputStream());
                    os.write("TLS Server: HELLO TLS CLIENT".getBytes());
                    os.flush();

                    System.out.println("------------------------------------------------------");
                }
            }
        }
    }
}

