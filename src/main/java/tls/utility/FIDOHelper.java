package tls.utility;

import apdu4j.core.ResponseAPDU;
import com.fasterxml.jackson.databind.node.ObjectNode;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.DecoderException;
import pro.javacard.fido2.cli.CLICallbacks;
import pro.javacard.fido2.cli.FIDOTool;
import pro.javacard.fido2.common.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.*;
import static pro.javacard.fido2.common.PINProtocols.*;

// TODO: Assertion not verified!!

public class FIDOHelper {

    public static byte[] getPinToken(KeyPair ephemeral, CTAP2Transport transport, String pin) throws IOException {
        ObjectNode response = ctap2(ClientPINCommand.getKeyAgreementV1().build(), transport);
        ECPublicKey deviceKey = P256.node2pubkey(response.get("keyAgreement"));
        byte[] sharedSecret = shared_secret(deviceKey, ephemeral);

        ObjectNode token = ctap2(CTAP2Commands.make_getPinToken(pin, deviceKey, ephemeral), transport);
        return PINProtocols.aes256_decrypt(sharedSecret, token.get("pinToken").binaryValue());
    }

    static byte[] fileOrHex(String pathOrHex) {
        Path path = Paths.get(pathOrHex);
        final String data;
        if (Files.exists(path)) {
            try {
                data = Files.readAllLines(path).get(0).trim();
                return Hex.decode(data);
            } catch (IOException e) {
                throw new IllegalArgumentException("Could not read file: " + e.getMessage(), e);
            }
        } else {
            data = pathOrHex;
        }
        try {
            return Hex.decode(data);
        } catch (DecoderException e) {
            return Base64.getUrlDecoder().decode(data);
        }
    }

    public static void register(byte[] clientDataHash, KeyPair ephemeral, CTAP2Transport transport, String domain, String pubKey, String credential, String pin, boolean rk) throws IOException {
        MakeCredentialCommand makeCredentialCommand = new MakeCredentialCommand();

        // Set clientdatahash
        makeCredentialCommand.withClientDataHash(clientDataHash);

        byte[] pinToken = getPinToken(ephemeral, transport, pin);

        // Set username and domain
        String[] components = domain.split("@");
        if (components.length != 2)
            throw new IllegalArgumentException("Invalid format for domain. Format: <username>@<domain.name>.com");
        makeCredentialCommand.withUserName(components[0]);
        makeCredentialCommand.withDomainName(components[1]);

        // Set user id (= hashed username)
        byte[] uid = PINProtocols.sha256(components[0].getBytes(StandardCharsets.UTF_8));
        makeCredentialCommand.withUserID(uid);

        // Optional: used resident keys
        if (rk) makeCredentialCommand.withOption("rk");

        // Set pin
        if (!pin.isEmpty()) makeCredentialCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));

        // Set algorithm
        makeCredentialCommand.withAlgorithm(COSEPublicKey.P256);

        // Construct command
        byte[] cmd = makeCredentialCommand.build();

        // Send to device
        final ObjectNode resp = CTAP2ProtocolHelpers.ctap2(cmd, transport);

        try {
            System.out.println("Registration: \n" + pretty(hexify(resp)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        Path credpath = Paths.get(credential);
        Path keypath = Paths.get(pubKey);
        AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(resp.get("authData").binaryValue());
        Files.writeString(credpath, Hex.toHexString(authenticatorData.getAttestation().getCredentialID()));
        Files.writeString(keypath, Hex.toHexString(COSEPublicKey.pubkey2bytes(authenticatorData.getAttestation().getPublicKey())));

        System.out.println("Authenticator data: \n" + pretty(authenticatorData.toJSON()));

        // TODO: verify attestation
        AttestationVerifier.dumpAttestation(makeCredentialCommand, resp);
        // If not U2F
        System.out.println("Used device:   " + authenticatorData.getAttestation().getAAGUID());
        System.out.println("Credential ID: " + Hex.toHexString(authenticatorData.getAttestation().getCredentialID()));
        System.out.println("Public key:    " + Hex.toHexString(COSEPublicKey.pubkey2bytes(authenticatorData.getAttestation().getPublicKey())));
    }

    public static void authenticate(byte[] clientDataHash, KeyPair ephemeral, CTAP2Transport transport, String domain, String pubkey, String pin) throws IOException, GeneralSecurityException {
        GetAssertionCommand getAssertionCommand = new GetAssertionCommand();

        getAssertionCommand.withClientDataHash(clientDataHash);

        if (domain.contains("@")) {
            // Use domain from name@domain
            String[] elements = domain.split("@");
            if (elements.length != 2) {
                throw new IllegalArgumentException("Invalid formation: " + domain);
            }
            getAssertionCommand.withDomain(elements[1]);
        } else if (domain.contains(".")) {
            // Plain domain
            getAssertionCommand.withDomain(domain);
        }

        getAssertionCommand.withOption("up", true);

        byte[] pinToken = getPinToken(ephemeral, transport, pin);

        // Set pin
        getAssertionCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));

        // Construct command
        byte[] cmd = getAssertionCommand.build();

        // Send to device
        final ObjectNode resp = ctap2(cmd, transport);

        byte[] authData = resp.get("authData").binaryValue();
        byte[] signature = resp.get(CTAP2Enums.GetAssertionResponseParameter.signature.name()).binaryValue();

        AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(authData);
        System.out.println("Authenticator data: \n" + pretty(hexify(authenticatorData.toJSON())));

        // Verify assertion, if pubkey given
        final PublicKey publicKey = CryptoUtils.bytes2pubkey(fileOrHex(pubkey));
        if (AssertionVerifier.verify(authenticatorData, clientDataHash, signature, publicKey)) {
            System.out.println("Verified OK.");
        } else {
            throw new GeneralSecurityException("Assertion not verified!");
        }
    }
}
