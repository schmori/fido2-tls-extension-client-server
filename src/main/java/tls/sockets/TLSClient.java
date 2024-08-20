package tls.sockets;

import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import org.json.JSONObject;
import tls.fidoServer.FIDOServer;
import tls.utility.AssertionResponseBuilder;
import tls.utility.CTAP2;
import tls.utility.WebAuthnAPI;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.beans.BeanDescriptor;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/*
* optional VM options: -Djavax.net.debug=ssl
*
* Purpose:
* This class will act as user client who wants to authenticate at a server.
* In this case, the server we want to authenticate at, is the TLSServer.
* */

public class TLSClient {

    private final static int PORT = 4321;
    private final static String USERNAME = "gloria";
    private final static String DOMAIN = "gloria@localhost";
    private final static String PUBKEY = "gloria-pubkey.txt";
    private final static String CREDENTIAL = "gloria-cred.txt";
    private final static String HOSTNAME = "localhost";
    private final static String PIN = "1234";
    private final static boolean RESIDENT_KEY = true;
    public static void main(String[] args) {
        try {
            startClient();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
    public static void startClient() throws IOException, InterruptedException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        params.setProtocols(new String[]{"TLSv1.3"});
        List<SNIServerName> serverNames = new ArrayList<>(1);
        serverNames.add(new SNIHostName("localhost"));
        params.setServerNames(serverNames);
        params.setFIDO(FIDO_MODE.WITH_NAME.getValue());
        if (FIDO_MODE.WITH_NAME.getValue() == 2) params.setFidoUsername(USERNAME); // später im zweiten handshake übertragen!
        SocketFactory factory = SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(HOSTNAME, PORT)) {
            System.out.println("Client started...");
            System.out.println("Possible fido modes: 0=none, 1=with id, 2=with name. Client chose: " + FIDO_MODE.WITH_NAME.getValue());
            socket.setSSLParameters(params);

            System.out.println("Start registration process");
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());

            // Registration: Send all necessary information to server
            String registration_message = DOMAIN + " " + PUBKEY + " " + CREDENTIAL + " " + PIN + " " + RESIDENT_KEY;
            os.write(registration_message.getBytes());
            os.flush();

            InputStream is = new BufferedInputStream(socket.getInputStream());
            byte[] data = new byte[2048];
            int len = is.read(data);
            int registered = Integer.parseInt(new String(data, 0, len));

            System.out.println((registered==1?"registered":"not registered"));

            // Assertion: Send all necessary information to server
            String assertion_message =  DOMAIN + " " + PUBKEY + " " + PIN;
            os.write(assertion_message.getBytes());
            os.flush();

            data = new byte[2048];
            len = is.read(data);
            int authenticated = Integer.parseInt(new String(data, 0, len));

            System.out.println((authenticated==1?"authenticated":"not authenticated"));
        }
    }

    public enum FIDO_MODE{
        NO_FIDO(0),
        WITH_ID(1),
        WITH_NAME(2);

        private final int value;

        FIDO_MODE(final int newValue) {
            value = newValue;
        }

        public int getValue() { return value; }
    }
}
