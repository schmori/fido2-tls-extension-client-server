package tls.sockets.server;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import pro.javacard.fido2.common.CTAP2ProtocolHelpers;
import pro.javacard.fido2.common.PINProtocols;
import tls.utility.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static tls.utility.Platform.*;

/* This class is used to register and authenticate users. */
public class FIDOServer {

    public static void main(String[] args) {
        // setup ldebug mode
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss:SSS");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
        CTAP2ProtocolHelpers.setProtocolDebug(System.out);

        FIDODatabase.createDatabase();

        try {
            startFIDOServer();
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static void startFIDOServer() throws IOException, GeneralSecurityException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();

        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(VARIABLES.FIDO_PORT)) {
            listener.setSSLParameters(params);

            byte[] ephemeralUserID = null;
            byte[] gcmKey = null;

            String username;
            byte[] uid;
            PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(VARIABLES.RPID, VARIABLES.RPNAME);
            PublicKeyCredentialUserEntity user = null;
            AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(VARIABLES.authenticatorAttachment, VARIABLES.residentKey, VARIABLES.userVerification);
            PublicKeyCredentialCreationOptions creationOptions = null;

            // Authentication data
            PublicKeyCredentialRequestOptions requestOptions = null;

            Logger.log("FIDO Server started");
            while (true) {
                try (Socket clientSocket = listener.accept()) {
                    Logger.log("FIDO Server: Accepted " + clientSocket);

                    DataInputStream dis = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
                    int request_len = dis.readInt();
                    byte[] request = dis.readNBytes(request_len);

                    String indication_number = new String(request);
                    Logger.log("FIDO Server: Indication number: " + indication_number);

                    switch (indication_number) { // receive ephemeralUserID
                        case "0" -> {
                            int len = dis.readInt();
                            ephemeralUserID = dis.readNBytes(len);

                            len = dis.readInt();
                            gcmKey = dis.readNBytes(len);
                            Logger.log("FIDO Server: Received ephemeralUserID and gcmKey.");
                        }
                        case "1" -> { // Receive username and set uid
                            int len = dis.readInt();
                            String fido = new String(dis.readNBytes(len));
                            len = dis.readInt();
                            username = new String(dis.readNBytes(len));
                            Logger.log("FIDO Server: Received username: " + username);
                            uid = PINProtocols.sha256(username.getBytes()); // 64 random bytes
                            if (fido.equals("0")) {
                                if (FIDODatabase.getPublicKey(Hex.toHexString(uid)) != null) throw new IOException("User already exists. Choose another username.");
                            }
                            user = new PublicKeyCredentialUserEntity(username, Hex.toHexString(uid), username);
                        }
                        case "2" -> { // Registration: Send PublicKeyCredentialCreationOptions to tls server
                            Logger.log("FIDO Server: Send PublicKeyCredentialCreationOptions to TLS server.");

                            byte[] challenge = new byte[32]; // at least 16 bytes long
                            try {
                                SecureRandom.getInstanceStrong().nextBytes(challenge);
                            } catch (NoSuchAlgorithmException e) {
                                throw new RuntimeException(e);
                            }

                            creationOptions = new PublicKeyCredentialCreationOptions(rp,
                                    user,
                                    Base64.getUrlEncoder().encodeToString(challenge),
                                    authenticatorSelection);

                            creationOptions.addPubKeyCredParam(new PublicKeyCredentialParameters("public-key", VARIABLES.CredentialAlg));

                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            byte[] serialized_options = serialize(creationOptions.toString());
                            dos.writeInt(serialized_options.length);
                            dos.write(serialized_options);
                            dos.flush();
                        }
                        case "3" -> {  // Registration
                            int len = dis.readInt();
                            byte[] response = dis.readNBytes(len);

                            JSONObject json = new JSONObject((String) deserialize(response));
                            Logger.log("FIDO Server: Received response data from TLS server: " + json);
                            assert creationOptions != null;
                            FIDOServerHelper.register(json, creationOptions.challenge, creationOptions.user);

                            // if is does return something to TLS Server, reg was successful
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            byte[] succeed = "1".getBytes();
                            dos.writeInt(succeed.length);
                            dos.write(succeed);
                            dos.flush();
                        }
                        case "4" -> { // send ephemeralUserID and gcmKey
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            dos.writeInt(ephemeralUserID.length);
                            dos.write(ephemeralUserID);
                            dos.writeInt(gcmKey.length);
                            dos.write(gcmKey);
                            dos.flush();
                            ephemeralUserID = null;
                            gcmKey = null;
                        }
                        case "5" -> { // Authentication: Send PublicKeyCredentialRequestOptions to tls server
                            Logger.log("FIDO Server: Send PublicKeyCredentialRequestOptions to TLS server.");

                            byte[] challenge = new byte[32]; // at least 16 bytes long
                            try {
                                SecureRandom.getInstanceStrong().nextBytes(challenge);
                            } catch (NoSuchAlgorithmException e) {
                                throw new RuntimeException(e);
                            }

                            requestOptions = new PublicKeyCredentialRequestOptions(Base64.getUrlEncoder().encodeToString(challenge), rp.rpid, VARIABLES.userVerification);

                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            byte[] serialized_options = serialize(requestOptions.toString());
                            dos.writeInt(serialized_options.length);
                            dos.write(serialized_options);
                            dos.flush();
                        }
                        case "6" -> {  // Authentication
                            int len = dis.readInt();
                            byte[] response = dis.readNBytes(len);

                            JSONObject json = new JSONObject((String) deserialize(response));
                            Logger.log("FIDO Server: Received response data from TLS server: " + json);
                            assert requestOptions != null;
                            FIDOServerHelper.authenticate(json, requestOptions.challenge);

                            // if is does return something to TLS Server, auth was successful
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            byte[] succeed = "1".getBytes();
                            dos.writeInt(succeed.length);
                            dos.write(succeed);
                            dos.flush();
                        }
                    }
                }
            }
        }
    }
}
