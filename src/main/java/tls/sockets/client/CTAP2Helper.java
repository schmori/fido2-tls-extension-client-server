package tls.sockets.client;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.util.encoders.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import pro.javacard.fido2.common.*;
import tls.utility.Logger;

import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.*;
import static pro.javacard.fido2.common.PINProtocols.*;
import static tls.utility.Platform.*;

public class CTAP2Helper {

    public static byte[] getPinToken(KeyPair ephemeral, CTAP2Transport transport, String pin) throws IOException {
        ObjectNode response = ctap2(ClientPINCommand.getKeyAgreementV1().build(), transport);
        ECPublicKey deviceKey = P256.node2pubkey(response.get("keyAgreement"));
        byte[] sharedSecret = shared_secret(deviceKey, ephemeral);

        ObjectNode token = ctap2(CTAP2Commands.make_getPinToken(pin, deviceKey, ephemeral), transport);
        return PINProtocols.aes256_decrypt(sharedSecret, token.get("pinToken").binaryValue());
    }

    public static byte[] getRegistrationResponse(CTAP2Transport transport, String pin, JSONObject options) throws IOException {
        MakeCredentialCommand makeCredentialCommand = new MakeCredentialCommand();

        JSONObject rp = new JSONObject(options.getString("rp"));
        JSONObject user = new JSONObject(options.getString("user"));
        JSONObject authenticatorSelection = new JSONObject(options.getString("authenticatorSelection"));
        String challenge = options.getString("challenge");
        JSONArray pubKeyCredParams = options.getJSONArray("pubKeyCredParams");

        ClientDataJSON clientDataJSON = new ClientDataJSON("webauthn.create", rp.getString("rpid"), challenge);
        byte[] clientDataHash = clientDataJSON.hash();

        // set ephemeral
        KeyPair ephemeral = P256.ephemeral();

        makeCredentialCommand.withClientDataHash(clientDataHash);

        byte[] pinToken = getPinToken(ephemeral, transport, pin);

        boolean rk = authenticatorSelection.getBoolean("requireResidentKey");

        makeCredentialCommand.withUserName(user.getString("username"));
        makeCredentialCommand.withDomainName(rp.getString("rpid"));

        makeCredentialCommand.withUserID(Hex.decode(user.getString("id")));

        if (rk) makeCredentialCommand.withOption("rk");

        if (!pin.isEmpty()) makeCredentialCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));

        int alg = pubKeyCredParams.getJSONObject(0).getInt("alg");
        if (alg == 1) {
            makeCredentialCommand.withAlgorithm(COSEPublicKey.P256);
        } else {
            // TODO: Choose different algorithm. Currently not implemented.
        }

        byte[] cmd = makeCredentialCommand.build();

        // Send to device
        final ObjectNode resp = CTAP2ProtocolHelpers.ctap2(cmd, transport);

        try {
            Logger.log("Registration: \n" + pretty(hexify(resp)));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        AttestationVerifier.dumpAttestation(makeCredentialCommand, resp);

        AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(resp.get("authData").binaryValue());

        Logger.log("Authenticator data: \n" + pretty(authenticatorData.toJSON()));

        AttestationObject attestationObject = new AttestationObject(authenticatorData.getAttestation().getAAGUID().toString(),
                Hex.toHexString(authenticatorData.getAttestation().getCredentialID()),
                Hex.toHexString(COSEPublicKey.pubkey2bytes(authenticatorData.getAttestation().getPublicKey())),
                authenticatorData.getAttestation().getLength());

        PublicKeyCreationResponse response = new PublicKeyCreationResponse(attestationObject, clientDataJSON);

        CTAP2Database.insertUser(user.getString("id"), serialize(ephemeral));

        return serialize(response.toString());
    }

    public static byte[] getAttestationResponse(CTAP2Transport transport, String pin, String username, JSONObject options) throws IOException {
        GetAssertionCommand getAssertionCommand = new GetAssertionCommand();

        String rpId = options.getString("rpId");
        String challenge = options.getString("challenge");
        String uv = options.getString("userVerification");

        ClientDataJSON clientDataJSON = new ClientDataJSON("webauthn.get", rpId, challenge);
        byte[] clientDataHash = clientDataJSON.hash();

        byte[] userHandle = PINProtocols.sha256(username.getBytes());
        KeyPair ephemeral = (KeyPair) deserialize(CTAP2Database.getKeyPair(Hex.toHexString(userHandle)));

        getAssertionCommand.withClientDataHash(clientDataHash);

        getAssertionCommand.withDomain(rpId);

        if (uv.equals("preferred")) getAssertionCommand.withOption("up", true);

        byte[] pinToken = getPinToken(ephemeral, transport, pin);

        // Set pin
        getAssertionCommand.withV1PinAuth(left16(hmac_sha256(pinToken, clientDataHash)));

        // Construct command
        byte[] cmd = getAssertionCommand.build();

        // Send to device
        final ObjectNode resp = ctap2(cmd, transport);

        PublicKeyRequestResponse response = new PublicKeyRequestResponse(clientDataJSON,
                Hex.toHexString(resp.get(CTAP2Enums.GetAssertionResponseParameter.authData.name()).binaryValue()),
                Hex.toHexString(resp.get(CTAP2Enums.GetAssertionResponseParameter.signature.name()).binaryValue()),
                Hex.toHexString(userHandle));

        return serialize(response.toString());
    }
}
