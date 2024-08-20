package tls.backup;

import org.json.JSONObject;
import tls.fidoServer.FIDOServer;
import tls.utility.AssertionResponseBuilder;
import tls.utility.WebAuthnAPI;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.Socket;
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
    private static FIDOServer fidoServer;
    public static void main(String[] args) {
        // Database.createDatabase(); // not needed right now, maybe for later

        try {
            startServer();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    static void startServer() throws IOException {
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

                    InputStream is = new BufferedInputStream(clientSocket.getInputStream());
                    byte[] data = new byte[2048];
                    int len = is.read(data);

                    String username = new String(data, 0, len);
                    System.out.println("Authenticate client: " + username);
                    String requestOptions = WebAuthnAPI.getOptionsJson(WebAuthnAPI.getRequestOptions(username));

                    OutputStream os = new BufferedOutputStream(clientSocket.getOutputStream());
                    os.write(requestOptions.getBytes(), 0, requestOptions.getBytes().length);
                    os.flush();

                    data = new byte[2048];
                    len = is.read(data);

                    String auth_data = new String(data, 0, len); // authenticator response
                    String[] each_auth_data = auth_data.split(" ");

                    JSONObject credentials = new JSONObject(each_auth_data[0]);
                    String signature = each_auth_data[1];
                    String rpIdHash = each_auth_data[2];
                    String counter = each_auth_data[3];
                    String credentialData = each_auth_data[4];

                    System.out.println("signatur: " + signature);

                    String requestId = WebAuthnAPI.requestId;
                    String credentialType = credentials.getJSONArray("allowCredentials").getJSONObject(0).getString("type");
                    String allowCredentials = credentials.getJSONArray("allowCredentials").getJSONObject(0).getString("id");
                    String clientDataJson = AssertionResponseBuilder.buildClientDataJson("webauthn.get", credentials.getString("challenge"), "https://localhost:8443");
                    String authenticatorData = AssertionResponseBuilder.buildAuthenticatorData(rpIdHash, "5", counter, credentialData, Optional.empty());

                    String finalResponse = "{\"requestId\":\"" + requestId + "\"," +
                            "\"credential\":{\"type\":\"" + credentialType +
                            "\",\"id\":\"" + allowCredentials +
                            "\",\"rawId\":\"" + allowCredentials +
                            "\",\"response\":" +
                            "{\"clientDataJSON\":\"" + clientDataJson +
                            "\",\"authenticatorData\":\"" + authenticatorData +
                            "\",\"signature\":\"" + signature +
                            "\",\"userHandle\":null},\"clientExtensionResults\":{}},\"sessionToken\":\"" + null + "\"}";

                    /*String authenticationRequest = new JSONObject()
                                    .put("requestId", WebAuthnAPI.requestId)
                                    .put("sessionToken", Optional.empty())
                                    .put("credential", new JSONObject(authenticatorData)).toString();

                    System.out.println("AuthenticatorRequest: " + authenticationRequest);*/

                    // AuthenticatorAssertionResponse
                    //PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc = PublicKeyCredential.parseAssertionResponseJson(authenticatorData);
                    //System.out.println("Did it work?");
                    //System.out.println(pkc.toString()); // --> FIXEN

                    String lol = "{\"requestId\":\"" + WebAuthnAPI.requestId + "\",\"credential\":{\"type\":\"public-key\",\"id\":\"y33AOB4JRHuU_0pg-poCnoxM5PefOQxbpYmREtc62ZbqKEq0GAS4MRma21Tr__1VWcrhDHYSryEKyC0z43howw\",\"rawId\":\"y33AOB4JRHuU_0pg-poCnoxM5PefOQxbpYmREtc62ZbqKEq0GAS4MRma21Tr__1VWcrhDHYSryEKyC0z43howw\",\"response\":{\"clientDataJSON\":\"" + clientDataJson + "\",\"authenticatorData\":\"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAACA\",\"signature\":\"" + signature + "\",\"userHandle\":null},\"clientExtensionResults\":{}},\"sessionToken\":\"puR54Kv-GC0572KEmoPfDe_wucx8k7kh_xLhcPd9fF4\"}";

                    boolean authenticated = WebAuthnAPI.authenticateUser(finalResponse);

                    os.write((authenticated?"1":"0").getBytes(), 0, 1);
                    os.flush();
                }
            }
        }
    }
}

