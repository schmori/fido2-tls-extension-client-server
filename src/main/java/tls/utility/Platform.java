package tls.utility;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONArray;
import org.json.JSONObject;
import pro.javacard.fido2.common.PINProtocols;

import java.io.*;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class Platform {

    public static byte[] serialize(final Object obj) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try (ObjectOutputStream out = new ObjectOutputStream(bos)) {
            out.writeObject(obj);
            out.flush();
            return bos.toByteArray();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static Object deserialize(byte[] bytes) {
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);

        try (ObjectInput in = new ObjectInputStream(bis)) {
            return in.readObject();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static class PublicKeyCredentialRequestOptions implements Serializable {
        public String challenge;
        public long timeout = 300000;
        public String rpId;
        public JSONArray allowCredentials;
        public String userVerification;
        public JSONArray extensions;

        public PublicKeyCredentialRequestOptions(String challenge, String rpId, String userVerification) {
            this.challenge = challenge;
            this.rpId = rpId;
            this.userVerification = userVerification;
        }

        public void addAllowCredential(PublicKeyCredentialDescriptor pubKeyCredDesc) {
            allowCredentials.put(new JSONObject(pubKeyCredDesc.toString()));
        }

        public String toString() {
            return new JSONObject()
                    .put("challenge", challenge)
                    .put("timeout", timeout)
                    .put("rpId", rpId)
                    .put("allowCredentials", allowCredentials)
                    .put("userVerification", userVerification)
                    .put("extensions", extensions).toString();
        }
    }

    public static class PublicKeyCredentialCreationOptions implements Serializable {

        public PublicKeyCredentialRpEntity rp;
        public PublicKeyCredentialUserEntity user;
        public String challenge;
        public JSONArray pubKeyCredParams;
        long timeout = 300000;
        public JSONArray excludeCredentials;
        public AuthenticatorSelectionCriteria authenticatorSelection;
        public String attestation = "none";
        public JSONArray extensions;

        public PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp,
                                                  PublicKeyCredentialUserEntity user,
                                                  String challenge,
                                                  AuthenticatorSelectionCriteria authenticatorSelection) {
            this.rp = rp;
            this.user = user;
            this.challenge = challenge;
            this.authenticatorSelection = authenticatorSelection;
            pubKeyCredParams = new JSONArray();
            excludeCredentials = new JSONArray();
        }

        public void addPubKeyCredParam(PublicKeyCredentialParameters pubKeyCredParam) {
            pubKeyCredParams.put(new JSONObject(pubKeyCredParam.toString()));
        }

        public void addExcludedCredential(PublicKeyCredentialDescriptor pubKeyCredDesc) {
            excludeCredentials.put(new JSONObject(pubKeyCredDesc.toString()));
        }

        public String toString() {
            return new JSONObject()
                    .put("rp", rp)
                    .put("user", user)
                    .put("challenge", challenge)
                    .put("pubKeyCredParams", pubKeyCredParams)
                    .put("timeout", timeout)
                    .put("excludeCredentials", excludeCredentials)
                    .put("authenticatorSelection", authenticatorSelection)
                    .put("attestation", attestation)
                    .put("extensions", extensions).toString();
        }
    }

    public static class PublicKeyCredentialRpEntity implements Serializable {
        public String rpid;
        public String rpname;

        public PublicKeyCredentialRpEntity(String rpid, String rpname) {
            this.rpid = rpid;
            this.rpname = rpname;
        }

        public String toString() {
            return new JSONObject()
                    .put("rpid", rpid)
                    .put("rpname", rpname).toString();
        }
    }

    public static class PublicKeyCredentialUserEntity implements Serializable {
        public String username;
        public String id;
        public String displayName;

        public PublicKeyCredentialUserEntity(String username, String id, String displayName) {
            this.username = username;
            this.id = id;
            this.displayName = displayName;
        }

        public String toString() {
            return new JSONObject()
                    .put("username", username)
                    .put("id", id)
                    .put("displayName", displayName).toString();
        }
    }

    public static class PublicKeyCredentialParameters implements Serializable {
        public String type;
        public int alg;

        public PublicKeyCredentialParameters(String type, int alg) {
            this.type = type;
            this.alg = alg;
        }

        public String toString() {
            return new JSONObject()
                    .put("type", type)
                    .put("alg", alg).toString();
        }
    }

    public static class PublicKeyCredentialDescriptor implements Serializable {
        public String type;
        public String id;
        public String[] transports;

        public PublicKeyCredentialDescriptor(String type, String id, String[] transports) {
            this.type = type;
            this.id = id;
            this.transports = transports;
        }

        public String toString() {
            return new JSONObject()
                    .put("type", type)
                    .put("id", id)
                    .put("transports", transports).toString();
        }
    }

    public static class AuthenticatorSelectionCriteria implements Serializable {
        public String authenticatorAttachment;
        public String residentKey;
        public boolean requireResidentKey = false;
        public String userVerification;

        public AuthenticatorSelectionCriteria(String authenticatorAttachment, String residentKey, String userVerification) {
            this.authenticatorAttachment = authenticatorAttachment;
            this.residentKey = residentKey;
            this.userVerification = userVerification;

            if (residentKey.equals("required")) this.requireResidentKey = true;
        }

        public String toString() {
            return new JSONObject()
                    .put("authenticatorAttachment", authenticatorAttachment)
                    .put("residentKey", residentKey)
                    .put("requireResidentKey", requireResidentKey)
                    .put("userVerification", userVerification).toString();
        }
    }

    public static class PublicKeyRequestResponse implements Serializable {
        public ClientDataJSON clientDataJSON;
        public String authenticatorData;
        public String signature;
        public String userHandle;

        public PublicKeyRequestResponse(ClientDataJSON clientDataJSON, String authenticatorData, String signature, String userHandle) {
            this.clientDataJSON = clientDataJSON;
            this.authenticatorData = authenticatorData;
            this.signature = signature;
            this.userHandle = userHandle;
        }

        public String toString() {
            return new JSONObject()
                    .put("clientDataJSON", clientDataJSON)
                    .put("authenticatorData", authenticatorData)
                    .put("signature", signature)
                    .put("userHandle", userHandle).toString();
        }
    }

    public static class PublicKeyCreationResponse implements Serializable {
        public AttestationObject attestationObject;
        public ClientDataJSON clientDataJSON;

        public PublicKeyCreationResponse(AttestationObject attestationObject, ClientDataJSON clientDataJSON) {
            this.attestationObject = attestationObject;
            this.clientDataJSON = clientDataJSON;
        }

        public String toString() {
            return new JSONObject()
                    .put("attestationObject", attestationObject)
                    .put("clientDataJSON", clientDataJSON).toString();
        }
    }

    public static class AttestationObject implements  Serializable {
        public String aaguid;
        public String credentialID;
        public String publicKey;
        public int length;
        public AttestationObject(String aaguid, String credentialID, String publicKey, int length) {
            this.aaguid = aaguid;
            this.credentialID = credentialID;
            this.publicKey = publicKey;
            this.length = length;
        }

        public String toString() {
            return new JSONObject()
                    .put("aaguid", aaguid)
                    .put("credentialID", credentialID)
                    .put("publicKey", publicKey)
                    .put("length", length).toString();
        }
    }

    public static class ClientDataJSON implements Serializable {
        public String type;
        public String origin;
        public String challenge;
        public ClientDataJSON(String type, String origin, String challenge) {
            this.type = type;
            this.origin = origin;
            this.challenge = challenge;
        }

        public String toString() {
            return new JSONObject()
                    .put("type", type)
                    .put("challenge", challenge)
                    .put("origin", origin).toString();
        }

        public byte[] hash() {
            return PINProtocols.sha256(toString().getBytes());
        }
    }
}
