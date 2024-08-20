package tls.sockets;

import org.hid4java.HidDevice;
import pro.javacard.fido2.cli.CLICallbacks;
import pro.javacard.fido2.cli.FIDOTool;
import pro.javacard.fido2.common.CTAP2Transport;
import pro.javacard.fido2.transports.USBTransport;
import tls.utility.FIDOHelper;
import tls.utility.Logger;

import javax.security.auth.callback.CallbackHandler;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;

public class TLSFIDOServer {

    static CallbackHandler handler;

    public static void main(String[] args) {
        handler = new CLICallbacks(); // contains logger

        HidDevice chosenOne = USBTransport.list().getFirst();
        CTAP2Transport transport = USBTransport.getInstance(chosenOne, handler);

        Logger.log(transport.toString());

        /*try {
            FIDOHelper.register(transport, "gloria@localhost.com", "gloria-pubkey.txt", "gloria-cred.txt", "1234", true);
            FIDOHelper.authenticate(transport, "gloria@localhost.com", "gloria-pubkey.txt", "1234");
        } catch (IOException | InterruptedException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }*/
    }
}
