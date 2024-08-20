package tls.fidoServer;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import tls.fidoServer.authenticator.Authenticator;
import tls.fidoServer.authenticator.AuthenticatorRepository;
import tls.fidoServer.user.AppUser;
import tls.fidoServer.user.UserRepository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class RegistrationService implements CredentialRepository {

    private final UserRepository userRepository = new UserRepository();

    private final AuthenticatorRepository authenticatorRepository = new AuthenticatorRepository();

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        AppUser user = userRepository.findByUsername(username);
        List<Authenticator> auth = authenticatorRepository.findAllByUser(user);
        return auth.stream()
                .map(credential -> PublicKeyCredentialDescriptor.builder()
                        .id(credential.getCredentialId())
                        .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        AppUser user = userRepository.findByUsername(username);
        return Optional.of(user.getHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        AppUser user = userRepository.findByHandle(userHandle);
        return Optional.of(user.getUsername());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<Authenticator> auth = authenticatorRepository.findByCredentialId(credentialId);
        return auth.map(credential -> RegisteredCredential.builder()
                .credentialId(credential.getCredentialId())
                .userHandle(credential.getUser().getHandle())
                .publicKeyCose(credential.getPublicKey())
                .signatureCount(credential.getCount())
                .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        Optional<Authenticator> auth = authenticatorRepository.findByCredentialId(credentialId);
        return auth.stream().map(credential -> RegisteredCredential.builder()
                        .credentialId(credential.getCredentialId())
                        .userHandle(credential.getUser().getHandle())
                        .publicKeyCose(credential.getPublicKey())
                        .signatureCount(credential.getCount())
                        .build())
                .collect(Collectors.toSet());
    }

    UserRepository getUserRepository() {
        return userRepository;
    }

    AuthenticatorRepository getAuthenticatorRepository() {
        return authenticatorRepository;
    }

}
