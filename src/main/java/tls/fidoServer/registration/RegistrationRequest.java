package tls.fidoServer.registration;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import lombok.Value;

import java.util.Optional;

@Value
public class RegistrationRequest {

    String username;
    Optional<String> credentialName;
    ByteArray requestId;
    PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
    Optional<ByteArray> sessionToken;
}
