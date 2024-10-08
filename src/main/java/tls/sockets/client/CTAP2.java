package tls.sockets.client;

import org.hid4java.HidDevice;
import org.json.JSONObject;
import pro.javacard.fido2.common.CTAP2ProtocolHelpers;
import pro.javacard.fido2.common.CTAP2Transport;
import pro.javacard.fido2.transports.USBTransport;
import tls.utility.Logger;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.Socket;
import java.util.Base64;

import static tls.utility.Platform.*;

public class CTAP2 {

    public static void main(String[] args) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
        System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
        System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "HH:mm:ss:SSS");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "trace");
        CTAP2ProtocolHelpers.setProtocolDebug(System.out);

        CTAP2Database.createDatabase();

        try {
            startCTAP2();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void startCTAP2() throws IOException {
        SSLParameters params = new SSLParameters();
        params.setCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});
        ServerSocketFactory factory = SSLServerSocketFactory.getDefault();

        try (SSLServerSocket listener = (SSLServerSocket) factory.createServerSocket(VARIABLES.CTAP2_PORT)) {
            byte[] ephemeralUserID = new byte[1];
            byte[] gcmKey = new byte[1];

            listener.setSSLParameters(params);
            Logger.log("CTAP2 server started");

            HidDevice chosenOne = USBTransport.list().getFirst();
            CTAP2Transport transport = USBTransport.getInstance(chosenOne, VARIABLES.handler);

            while (true) {
                try (Socket clientSocket  = listener.accept()) {
                    Logger.log("CTAP2 server: Accepted " + clientSocket);

                    DataInputStream dis = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
                    int request_len = dis.readInt();
                    byte[] request = dis.readNBytes(request_len);

                    String indication_number = new String(request);
                    Logger.log("CTAP2 Server: Indication number: " + indication_number);

                    switch (indication_number) {
                        case "0" -> { // receive ephemeralUserID and gcmKey
                            int len = dis.readInt();
                            ephemeralUserID = dis.readNBytes(len);

                            len = dis.readInt();
                            gcmKey = dis.readNBytes(len);
                            Logger.log("CTAP2 Server: Received ephemeralUserID and gcmKey.");
                        }
                        case "1" -> { // registration: receive PublicKeyCredentialCreationOptions from TLS Client
                            int len = dis.readInt();
                            byte[] serializedOptions = dis.readNBytes(len);
                            JSONObject json = new JSONObject((String) deserialize(serializedOptions));

                            byte[] response = CTAP2Helper.getRegistrationResponse(transport, VARIABLES.PIN, json);
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            dos.writeInt(response.length);
                            dos.write(response);
                            dos.flush();
                        }
                        case "2" -> { // send ephemeralUserID and gcmKey
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            dos.writeInt(ephemeralUserID.length);
                            dos.write(ephemeralUserID);
                            dos.writeInt(gcmKey.length);
                            dos.write(gcmKey);
                            dos.flush();
                            ephemeralUserID = new byte[1];
                            gcmKey = new byte[1];
                        }
                        case "3" -> { // authentication: receive PublicKeyCredentialRequestOptions from TLS Client
                            int len = dis.readInt();
                            byte[] serializedOptions = dis.readNBytes(len);
                            JSONObject json = new JSONObject((String) deserialize(serializedOptions));

                            byte[] response = CTAP2Helper.getAttestationResponse(transport, VARIABLES.PIN, VARIABLES.USERNAME, json);
                            DataOutputStream dos = new DataOutputStream(new BufferedOutputStream(clientSocket.getOutputStream()));
                            dos.writeInt(response.length);
                            dos.write(response);
                            dos.flush();
                        }
                    }
                }
            }
        }
    }

}
