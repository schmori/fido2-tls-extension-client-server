package tls.fidoServer.authenticator;

import com.yubico.webauthn.data.ByteArray;
import tls.fidoServer.authenticator.Authenticator;
import tls.fidoServer.user.AppUser;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public class AuthenticatorRepository {
    private Node head;

    public void addAuthenticator(Authenticator authenticator) {
        Node newNode = new Node(authenticator);
        if (head == null) {
            head = newNode;
        } else {
            Node current = head;
            while (current.next != null) {
                current = current.next;
            }
            current.next = newNode;
        }
    }

    public Optional<Authenticator> findByCredentialId(ByteArray credentialId) {
        Node current = head;
        while (current != null) {
            if (Objects.equals(current.authenticator.getCredentialId(), credentialId)) {
                return Optional.ofNullable(current.authenticator);
            }
            current = current.next;
        }
        return Optional.empty();
    }

    public List<Authenticator> findAllByUser(AppUser user) {
        Node current = head;
        List<Authenticator> authenticators = new ArrayList<>();
        while (current != null) {
            if (Objects.equals(current.authenticator.getUser(), user)) {
                authenticators.add(current.authenticator);
            }
            current = current.next;
        }
        return authenticators;
    }

    private static class Node {
        Authenticator authenticator;
        Node next;

        Node(Authenticator authenticator) {
            this.authenticator = authenticator;
        }
    }
}
