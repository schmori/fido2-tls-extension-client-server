package tls.fidoServer.user;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;

public class AppUser {

    private long id;
    private final String username;
    private final String displayName;
    private final ByteArray handle;

    public AppUser(UserIdentity userIdentity) {
        this.handle = userIdentity.getId();
        this.username = userIdentity.getName();
        this.displayName = userIdentity.getDisplayName();
    }

    public UserIdentity toUserIdentity() {
        return UserIdentity.builder()
                .name(getUsername())
                .displayName(getDisplayName())
                .id(getHandle())
                .build();
    }

    public long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public ByteArray getHandle() {
        return handle;
    }
}
