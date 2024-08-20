package tls.fidoServer.user;

import com.yubico.webauthn.data.ByteArray;
import tls.fidoServer.user.AppUser;

import java.util.Objects;

public class UserRepository {
    private Node head;

    public void addUser(AppUser user) {
        Node newNode = new Node(user);
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

    public AppUser findByUsername(String username) {
        Node current = head;
        while (current != null) {
            if (Objects.equals(current.user.getUsername(), username)) {
                return current.user;
            }
            current = current.next;
        }
        return null;
    }

    public AppUser findByHandle(ByteArray handle) {
        Node current = head;
        while (current != null) {
            if (Objects.equals(current.user.getHandle(), handle)) {
                return current.user;
            }
            current = current.next;
        }
        return null;
    }

    private static class Node {
        AppUser user;
        Node next;

        Node(AppUser user) {
            this.user = user;
        }
    }
}