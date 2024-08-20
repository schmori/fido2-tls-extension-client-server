package tls.sockets;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import org.hid4java.HidDevice;
import org.json.JSONArray;
import org.json.JSONObject;
import pro.javacard.fido2.cli.CLICallbacks;
import pro.javacard.fido2.common.CTAP2Transport;
import pro.javacard.fido2.common.CryptoUtils;
import pro.javacard.fido2.common.P256;
import pro.javacard.fido2.transports.USBTransport;
import tls.fidoServer.FIDOServer;
import tls.utility.AssertionResponseBuilder;
import tls.utility.CTAP2;
import tls.utility.FIDOHelper;
import tls.utility.WebAuthnAPI;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import javax.security.auth.callback.CallbackHandler;
import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Optional;

/*
 * optional VM options: -Djavax.net.debug=ssl
 *
 * This class acts as TLS server.
 * For registration, we will use https as usual.
 * But for authentication, we will use TLS.
 * */

public class TLSServer {
    private final static int PORT = 4321;
    static CallbackHandler handler;
    private static byte[] clientDataHash = null;
    private static KeyPair ephemeral = null;
    public static void main(String[] args) {
        // Database.createDatabase(); // not needed right now, maybe for later

        try {
            startServer();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static void startServer() throws IOException, GeneralSecurityException {
        handler = new CLICallbacks(); // contains logger

        // TODO: for now its fine, but has to be changed later
        clientDataHash = CryptoUtils.random(32);
        ephemeral = P256.ephemeral();

        HidDevice chosenOne = USBTransport.list().getFirst();
        CTAP2Transport transport = USBTransport.getInstance(chosenOne, handler);

        SSLParameters params = new SSLParameters();
        params.setNeedClientAuth(true);
        params.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        params.setProtocols(new String[]{"TLSv1.3"});
        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();
        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(PORT)) {
            listener.setSSLParameters(params);
            System.out.println("Server started. Listening for messages...");
            while (true) {
                try (Socket clientSocket = listener.accept()) {
                    System.out.println("Accepted " + clientSocket);

                    // Register: Receive all necessary information from client
                    InputStream is = new BufferedInputStream(clientSocket.getInputStream());
                    byte[] data = new byte[2048];
                    int len = is.read(data);

                    String[] registration_message = new String(data, 0, len).split(" ");
                    String domain = registration_message[0];
                    String pubkey = registration_message[1];
                    String credential = registration_message[2];
                    String pin = registration_message[3];
                    String rk = registration_message[4];
                    System.out.println("Register client: " + domain);
                    FIDOHelper.register(clientDataHash, ephemeral, transport, domain, pubkey, credential, pin, (rk.equals("1")));

                    // If successful, no error is thrown
                    OutputStream os = new BufferedOutputStream(clientSocket.getOutputStream());
                    os.write("1".getBytes(), 0, 1);
                    os.flush();

                    // Assertion: Receive all necessary information from client
                    data = new byte[2048];
                    len = is.read(data);

                    String[] assertion_message = new String(data, 0, len).split(" ");
                    domain = assertion_message[0];
                    pubkey = assertion_message[1];
                    pin = assertion_message[2];

                    // If successful, no error is thrown
                    FIDOHelper.authenticate(clientDataHash, ephemeral, transport, domain, pubkey, pin);

                    os.write("1".getBytes(), 0, 1);
                    os.flush();
                }
            }
        }
    }
}

