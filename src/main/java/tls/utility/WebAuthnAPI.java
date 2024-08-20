package tls.utility;

import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class WebAuthnAPI {

    private static HttpsURLConnection connection = null;
    public static String requestId;
    private static final SSLContext sslContext; // create context to avoid error "unable to find valid certification path to requested target"

    static {
        try {
            sslContext = SSLContext.getInstance("TLS");

            sslContext.init(null, new TrustManager[] { new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                }
            } }, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean authenticateUser(String authenticatorResponse) {
        try {
            String serverUrl = "https://localhost:8443/api/v1/authenticate/finish";
            connection = getHttpsAuthenticateURLConnection(serverUrl, sslContext, authenticatorResponse);
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = connection.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                return true;
            } else {
                System.out.println("Fehler beim Abrufen der Daten. Antwortcode: " + responseCode);
            }

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /*
    * Get "PublicKeyCredentialRequestOptions" from WebAuthn-Server
    * */
    public static String getRequestOptions(String username) {
        try {
            String serverUrl = "https://localhost:8443/api/v1/authenticate";
            connection = getHttpsRequestURLConnection(username, serverUrl, sslContext);
            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                InputStream inputStream = connection.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                System.out.println("PublicKeyCredentialOptions: " + response);
                return response.toString();
            } else {
                System.out.println("Fehler beim Abrufen der Daten. Antwortcode: " + responseCode);
            }

            connection.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static HttpsURLConnection getHttpsRequestURLConnection(String username, String serverUrl, SSLContext sslContext) throws IOException {
        URL url = new URL(serverUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        // deactivate hostname check (otherwise error "No name matching localhost found" is thrown)
        connection.setHostnameVerifier((hostname, session) -> true);

        // im fn modus, muss der nutzername noch mit übergeben werden

        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        String encodedUrl = "username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
        final BufferedWriter bfw = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
        bfw.write(encodedUrl);
        bfw.flush();
        bfw.close();

        return connection;
    }

    private static HttpsURLConnection getHttpsAuthenticateURLConnection(String serverUrl, SSLContext sslContext, String authenticatorResponse) throws IOException {
        URL url = new URL(serverUrl);
        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        // deactivate hostname check (otherwise error "No name matching localhost found" is thrown)
        connection.setHostnameVerifier((hostname, session) -> true);

        // im fn modus, muss der nutzername noch mit übergeben werden

        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "text/plain");

        final BufferedWriter bfw = new BufferedWriter(new OutputStreamWriter(connection.getOutputStream()));
        bfw.write(authenticatorResponse);
        bfw.flush();
        bfw.close();

        // [truncated]{"requestId":"9jK1jEilEN5XUKcqHcpNLWxLuP2NN7tpQZN8p54IbeQ","credential":{"type":"public-key","id":"88byMQmx9OBOmQ7vx-iG09VCK-t8QbkZrdwbnMYwrohwRE0IG-73yR3BTtqct3AjNOfEk7JeZL8qw5waFEwlvQ","rawId":"88byMQmx9OBOmQ7vx-iG09VCK-t8Qbk

        return connection;
    }

    public static String getOptionsJson(String request) {
        JSONObject jsonObject = new JSONObject(request);
        requestId = jsonObject.getJSONObject("request").getString("requestId");
        JSONObject pubCredRequestOptions = jsonObject.getJSONObject("request").getJSONObject("publicKeyCredentialRequestOptions"); // reihenfolge der attribute geändert, KEIN bug
        return String.valueOf(pubCredRequestOptions).replace("\"", "*");
    }
}
