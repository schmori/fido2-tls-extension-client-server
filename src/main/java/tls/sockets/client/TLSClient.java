package tls.sockets.client;

import tls.utility.Logger;

import javax.net.SocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;

/*
* optional VM options: -Djavax.net.debug=ssl:handshake
* */

public class TLSClient {
    public static void main(String[] args) {
        try {
            startTLSClient();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    static void setAuthenticationScheme() {
        String systemPath = System.getProperty("user.dir");
        String sep = System.getProperty("file.separator");

        System.setProperty("javax.net.ssl.keyStore", systemPath+sep+"src"+sep+"main"+sep+"resources"+sep+"clientkeystore.p12");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
        System.setProperty("javax.net.ssl.trustStore", systemPath+sep+"src"+sep+"main"+sep+"resources"+sep+"clienttruststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");
    }
    public static void startTLSClient() throws IOException, InterruptedException {
        setAuthenticationScheme();

        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        params.setProtocols(new String[]{"TLSv1.3"});

        SocketFactory factory = SSLSocketFactory.getDefault();

        params.setFIDO(VARIABLES.FIDO);
        params.setTicket(VARIABLES.TICKET.getBytes());
        params.setUsername(VARIABLES.USERNAME);

        ClientSocket(params, factory, "First Handshake: Either Pre Registration or Authentication");

        System.out.println("------------------------------------------------------");

        ClientSocket(params, factory, "Second Handshake: Either Registration or Authentication");
    }

    private static void ClientSocket(SSLParameters params, SocketFactory factory, String mode) throws IOException {
        try (SSLSocket socket = (SSLSocket) factory.createSocket(VARIABLES.HOSTNAME, VARIABLES.TLS_PORT)) {
            Logger.log("TLS Client started: " + mode);
            socket.setSSLParameters(params);

            OutputStream os = new BufferedOutputStream(socket.getOutputStream());
            os.write("TLS Client: HELLO TLS SERVER".getBytes());
            os.flush();

            InputStream is = new BufferedInputStream(socket.getInputStream());
            byte[] data = new byte[2048];
            int len = is.read(data);

            String message = new String(data, 0, len);
            Logger.log("TLS Client: Received message by TLS Server: " + message);

            socket.getSession().invalidate();
        }
    }
}
