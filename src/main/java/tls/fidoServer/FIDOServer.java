package tls.fidoServer;

/*
* This classes purpose is to register and authenticate the TLSClient.
* It is directly connected to the TLSServer.
* */

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.Getter;
import tls.database.Database;
import tls.fidoServer.authenticator.Authenticator;
import tls.fidoServer.helper.SessionManager;
import tls.fidoServer.helper.Utility;
import tls.fidoServer.registration.RegistrationRequest;
import tls.fidoServer.user.AppUser;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

public class FIDOServer {
    @Getter
    private final RegistrationService service;
    @Getter
    private final RelyingParty relyingParty;
    // private final InMemoryRegistrationStorage userStorage;
    private static final SecureRandom random = new SecureRandom();
    private final SessionManager sessions = new SessionManager();
    private RegistrationRequest registerRequest;
    private static String registrationCredentialJSON;
    private static AssertionRequest request;

    public FIDOServer() {
        service = new RegistrationService();
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id("localhost")
                .name("FIDO Server")
                .build();
        relyingParty = RelyingParty.builder()
                .identity(identity)
                .credentialRepository(service)
                .origins(Collections.singleton("https://localhost:8443")) // origins notwendig? eventuell löschen
                .build();
        registerRequest = null;
    }

    // *** REGISTRATION ***


    /*
    * Diese Methode speichert den neuen User in meiner Datenbank und ruft danach
    * eine Methode auf, welche die Funktion startRegistration aufruft
    * */
    public void newUserRegistration(String username, String displayName) {
        AppUser existingUser = service.getUserRepository().findByUsername(username);

        if (existingUser == null) { // pro session wird eine neue id generiert, also kann in unterschiedlichen sessions zb der user "test" mehrmals erstellt werden aber mit unterschiedlichen ids

            UserIdentity userIdentity = UserIdentity.builder()
                    .name(username)
                    .displayName(displayName)
                    .id(Utility.generateRandomId(32))
                    .build();

            AppUser newUser = new AppUser(userIdentity);
            service.getUserRepository().addUser(newUser);
            newAuthRegistration(newUser);
        } else {
            System.out.println("Username " + username + " already exists. Choose another name.");
            // throw new RuntimeException("Username " + username + " already exists. Choose another name.");
        }
    }

    public void newAuthRegistration(AppUser user) {
        AppUser existingUser = service.getUserRepository().findByHandle(user.getHandle());
        if (existingUser != null) {
            UserIdentity userIdentity = user.toUserIdentity();
            StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .build();
            try {
                registerRequest =
                        new RegistrationRequest(
                                registrationOptions.getUser().getName(),
                                Optional.of(registrationOptions.getUser().getName()),
                                generateRandom(32),
                                relyingParty.startRegistration(
                                        StartRegistrationOptions.builder()
                                                .user(userIdentity)
                                                .authenticatorSelection(
                                                        AuthenticatorSelectionCriteria.builder()
                                                                .residentKey(ResidentKeyRequirement.PREFERRED)
                                                                .build())
                                                .build()),
                        Optional.of(sessions.createSession(userIdentity.getId())));
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            }
            // Store user in database
            Database.insertUser(registrationOptions.getUser().getId().getBase64(), registrationOptions.getUser().getName(), registrationOptions.getUser().getDisplayName());
            PublicKeyCredentialCreationOptions registration = relyingParty.startRegistration(registrationOptions);
            try {
                registrationCredentialJSON = registration.toCredentialsCreateJson();
                System.out.println("Registration Credential JSON:");
                System.out.println(registrationCredentialJSON); // das ist die request → muss ins finishRegistration gegeben werden!
                //finishRegistration(registrationCredentialJSON, registrationOptions.getUser().getName(), registrationOptions.getUser().getName());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        } else {
            throw new RuntimeException("User " + user.getUsername() + " does not exist. Please register.");
        }
    }

    public void finishRegistration(String credential, String username, String credentialName) {
        try {
            AppUser user = service.getUserRepository().findByUsername(username);
            PublicKeyCredentialCreationOptions requestOptions = registerRequest.getPublicKeyCredentialCreationOptions();
            if (requestOptions != null) {
                //String response = // hier muss die response generiert werden, aber das mach ich jetzt einfach über den web browser (java-webauthn-server)
                System.out.println(PublicKeyCredential.parseRegistrationResponseJson(credential));
                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential.parseRegistrationResponseJson(credential);
                FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                        .request(requestOptions)
                        .response(pkc)
                        .build();
                RegistrationResult result = relyingParty.finishRegistration(options);
                Authenticator savedAuth = new Authenticator(result, pkc.getResponse(), user, credentialName);
                service.getAuthenticatorRepository().addAuthenticator(savedAuth);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (RegistrationFailedException e) {
            throw new RuntimeException(e);
        }
    }

    private static ByteArray generateRandom(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }

    public void startAuthentication(String username) {
        //String request = WebAuthnAPI.getRequestOptions(); // nur wenn der user existiert, kommt hier ein json-string zurück
        request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .build());
        try {
            System.out.println("Request Credential JSON");
            System.out.println(request.toCredentialsGetJson()); // das muss  
            //return request.toCredentialsGetJson(); // das stimmt und kann so bleiben!!
            //finishAuthentication(request.toCredentialsGetJson(), "gloria", request);
        } catch (JsonProcessingException e) {
            System.out.println(e.getMessage());
        }
    }

    public void finishAuthentication(String credential, String username) {
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc = PublicKeyCredential.parseAssertionResponseJson(credential);
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());
            if (result.isSuccess()) {
                System.out.println("User with name " + username + " is authenticated.");
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (AssertionFailedException e) {
            throw new RuntimeException(e);
        }
    }

    public String getRegistrationCredentialJSON() {
        return registrationCredentialJSON;
    }
}
