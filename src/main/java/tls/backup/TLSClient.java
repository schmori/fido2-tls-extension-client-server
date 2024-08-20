package tls.backup;

import tls.utility.CTAP2;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

/*
* optional VM options: -Djavax.net.debug=ssl
*
* Purpose:
* This class will act as user client who wants to authenticate at a server.
* In this case, the server we want to authenticate at, is the TLSServer.
* */

public class TLSClient {

    // FINISH AUTH {"requestId":"JZQMAZNCgt9jWvH2XqW6WenKe8hA5StRx2NzfExLQ1o","credential":{"type":"public-key","id":"muKJ59wFLGpLsUGtgfdZcMvfSTj6eFA_RlYL_44upfomgneVoUEmj7lCnkCANku9xvz02KYgPbzvQQsMYN4jSA","rawId":"muKJ59wFLGpLsUGtgfdZcMvfSTj6eFA_RlYL_44upfomgneVoUEmj7lCnkCANku9xvz02KYgPbzvQQsMYN4jSA","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJEbnFMeDRJcGlVcklSSU5HNm1kOEdoZnFtVnI1b3ZCZ1JYeEQ3QWJxQk9BIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAACQ","signature":"MEQCIDShkW0vd0YAM1Whtoqsa_lfwLJaSaqze1uwIamkxdE1AiBjY0UiSB6msUmKVAr1_FxGAJZon4zCT42k3_wtIKgwQw","userHandle":null},"clientExtensionResults":{}},"sessionToken":"cUIKeHVPqOOmVvzDOin5k6ifXP-3b0ZDH-iv0BdK2uE"}

    private final static String USERNAME = "gloria";
    private final static int PORT = 4321;
    private final static String HOSTNAME = "localhost";
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

            System.out.println("Start authentication process");
            OutputStream os = new BufferedOutputStream(socket.getOutputStream());

            // Send username to server
            os.write(USERNAME.getBytes());
            os.flush();

            InputStream is = new BufferedInputStream(socket.getInputStream());
            byte[] data = new byte[2048];
            int len = is.read(data);

            // receive PublicKeyCredentialRequestOptions from server
            String regCredJSON = new String(data, 0, len);
            //System.out.println("RequestOptions: " + regCredJSON);
            CTAP2.doCTAP2(regCredJSON);

            // Generate assertion response from authenticator
            String credentials = regCredJSON.replace("*", "\"");
            //JSONObject jsonObject = new JSONObject(credentials);
            //System.out.println("Credentials: " + credentials);

            // String type, String pkId, String challenge, String origin, String signature, String clientDataJSON, String authenticatorData, String userHandle, String clientExtensionResults

            //String finalResponseToTLSServer = "{"requestId":"WgAA60vfGrPW0HCDMMxeZohbvYFpVp6aJQifYPGlnO0","credential":{"type":"public-key","id":"5-2zzH0dEcBBIfSEuEZe3Y2_wVNG1cey8yh6jpWyDoXalQeD25f529UMS0kncSWHVmdHY0HHG0IaU1eNfOt5nA","rawId":"5-2zzH0dEcBBIfSEuEZe3Y2_wVNG1cey8yh6jpWyDoXalQeD25f529UMS0kncSWHVmdHY0HHG0IaU1eNfOt5nA","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiItYURPakhHY2lCUjRfX0pZVnZCenFQSHpLclZGQmxXTWhTX1IwNW5mS3lRIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAEg","signature":"MEQCIFSFgnaFXkqvPSa0nmEJXa3LCuixr-rmM5p94zqpFmsoAiAn_h6EBJJYd1w3U60SfqfZCJnIshCe-R5wt8ZslXvnVg","userHandle":null},"clientExtensionResults":{}},"sessionToken":"ixCAcKv3m20fdNJJa9EieNN4v5aCbCm58-LZpF_0qiU"}";

            /*String authenticatorResponse = AssertionResponseBuilder.buildCredentialJson(jsonObject.getJSONArray("allowCredentials").getJSONObject(0).getString("type"),
                    jsonObject.getJSONArray("allowCredentials").getJSONObject(0).getString("id"),
                    jsonObject.getString("challenge"),
                    "https://localhost:8443",
                    CTAP2.signature,
                    AssertionResponseBuilder.buildClientDataJson("webauthn.get", jsonObject.getString("challenge"), "https://localhost:8443"),
                    AssertionResponseBuilder.buildAuthenticatorData(CTAP2.rpIdHash, "5", CTAP2.counter, Optional.empty(), Optional.empty()),
                    "",
                    "",
                    jsonObject.getJSONArray("allowCredentials").getJSONObject(0).getString("id"));*/

            String auth_data = credentials + " " + CTAP2.signature + " " +  CTAP2.rpIdHash + " " + CTAP2.counter + " " + CTAP2.credentialData;
            os.write(auth_data.getBytes());
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
