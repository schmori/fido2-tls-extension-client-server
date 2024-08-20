package tls.fidoServer.authenticator;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import tls.fidoServer.user.AppUser;

import java.util.Optional;

public class Authenticator {

    private Long id;
    private final String name;
    private final ByteArray credentialId;
    private final ByteArray publicKey;
    private final AppUser user;
    private final Long count;
    private ByteArray aaguid;

    public Authenticator(RegistrationResult result,
                         AuthenticatorAttestationResponse response,
                         AppUser user,
                         String name) {
        Optional<AttestedCredentialData> attestedCredentialData = response.getAttestation()
                .getAuthenticatorData()
                .getAttestedCredentialData();
        this.credentialId = result.getKeyId().getId();
        this.publicKey = result.getPublicKeyCose();
        attestedCredentialData.ifPresent(credentialData -> this.aaguid = credentialData.getAaguid());
        this.count = result.getSignatureCount();
        this.name = name;
        this.user = user;
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public ByteArray getCredentialId() {
        return credentialId;
    }

    public ByteArray getPublicKey() {
        return publicKey;
    }

    public AppUser getUser() {
        return user;
    }

    public Long getCount() {
        return count;
    }

    public ByteArray getAaguid() {
        return aaguid;
    }
}
