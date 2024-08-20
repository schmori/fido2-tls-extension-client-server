package tls.fidoServer.helper;

import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;

public class Utility {

    private static final SecureRandom random = new SecureRandom();

    public static ByteArray generateRandomId(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return new ByteArray(bytes);
    }
}
