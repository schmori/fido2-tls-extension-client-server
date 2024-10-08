package tls.sockets.client;

import pro.javacard.fido2.cli.CLICallbacks;

import javax.security.auth.callback.CallbackHandler;

public class VARIABLES {

    public final static int TLS_PORT = 4321;
    public final static String FIDO = "1";
    public final static String HOSTNAME = "localhost";
    public final static String PIN = "1234";
    public final static int CTAP2_PORT = 5555;
    public final static CallbackHandler handler = new CLICallbacks();
    public final static String TICKET = "clientticket";
    public final static String USERNAME = "melanie";
}
