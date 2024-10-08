package tls.sockets.server;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;
import pro.javacard.fido2.common.AssertionVerifier;
import pro.javacard.fido2.common.AuthenticatorData;
import pro.javacard.fido2.common.CryptoUtils;
import pro.javacard.fido2.common.PINProtocols;
import tls.utility.Logger;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.hexify;
import static pro.javacard.fido2.common.CTAP2ProtocolHelpers.pretty;
import static tls.utility.Platform.PublicKeyCredentialUserEntity;

public class FIDOServerHelper {

    public static void register(JSONObject response, String original_challenge, PublicKeyCredentialUserEntity user) throws IOException {
        JSONObject clientDatJson = new JSONObject(response.getString("clientDataJSON"));

        String origin = clientDatJson.getString("origin");
        String challenge = clientDatJson.getString("challenge");
        String type = clientDatJson.getString("type");

        if (!VARIABLES.RPID.equals(origin))
            throw new IOException("origin does not match rpID. origin: " + origin + " <> " + "rpID: " + VARIABLES.RPID);
        if (!"webauthn.create".equals(type))
            throw new IOException("type does not match webauthn.get.");
        if (!original_challenge.equals(challenge))
            throw new IOException("challenges do not match. Original challenge: " + original_challenge + " <> Sent challenge: " + challenge);

        JSONObject attestationObject = new JSONObject(response.getString("attestationObject"));
        String publicKey = attestationObject.getString("publicKey");

        Logger.log("Used device:   " + attestationObject.getString("aaguid"));
        Logger.log("Credential ID: " + attestationObject.getString("credentialID"));
        Logger.log("Public key:    " + publicKey);

        FIDODatabase.insertUser(user.id, user.username, user.displayName);
        FIDODatabase.insertCredential(attestationObject.getString("credentialID"),
                publicKey, user.id);
    }

    public static void authenticate(JSONObject response, String original_challenge) throws IOException, GeneralSecurityException {
        JSONObject clientDataJson = new JSONObject(response.getString("clientDataJSON"));
        byte[] clientDataHash = PINProtocols.sha256(clientDataJson.toString().getBytes());

        if (!VARIABLES.RPID.equals(clientDataJson.getString("origin")))
            throw new IOException("origin does not match rpID. origin: " + clientDataJson.getString("origin") + " <> " + "rpID: " + VARIABLES.RPID);
        if (!"webauthn.get".equals(clientDataJson.getString("type")))
            throw new IOException("type does not match webauthn.get.");
        if (!original_challenge.equals(clientDataJson.getString("challenge")))
            throw new IOException("challenges do not match. Original challenge: " + original_challenge + " <> Sent challenge: " + clientDataJson.getString("challenge"));

        byte[] authData = Hex.decode(response.getString("authenticatorData"));
        byte[] signature = Hex.decode(response.getString("signature"));

        AuthenticatorData authenticatorData = AuthenticatorData.fromBytes(authData);
        Logger.log("Authenticator data: \n" + pretty(hexify(authenticatorData.toJSON())));

        String publicKey_string = FIDODatabase.getPublicKey(response.getString("userHandle"));

        Logger.log("----------- Authenticate the following user: ------------");
        Logger.log("User Handle: " + response.getString("userHandle"));
        Logger.log("Public Key: " + publicKey_string);
        Logger.log("-----------------------");

        // Verify assertion, if pubkey given
        final PublicKey publicKey = CryptoUtils.bytes2pubkey(Hex.decode(publicKey_string));

        Logger.log(String.valueOf(publicKey));

        if (AssertionVerifier.verify(authenticatorData, clientDataHash, signature, publicKey)) {
            Logger.log("Verified OK.");
        } else {
            throw new GeneralSecurityException("Assertion not verified!");
        }
    }
}