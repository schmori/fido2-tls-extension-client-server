package tls.utility;

import com.yubico.webauthn.data.ByteArray;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class AssertionResponseBuilder {

    // {"requestId":"j0avEa3sQKVQNxwKy1jeGf5RmDPkoeJiFWciV1hJiI0","credential":{"type":"public-key","id":"BE2HXdsgHxuSz5_daywR8Juq-NVIO9L35pkhyBN6cQzZEFrA1OuCaHuOLXZBl7NmXVsDMBMkfmQ6QscLG2V7aw","rawId":"BE2HXdsgHxuSz5_daywR8Juq-NVIO9L35pkhyBN6cQzZEFrA1OuCaHuOLXZBl7NmXVsDMBMkfmQ6QscLG2V7aw","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJkTkZWcW5ja2V4TU5YYnYtZ3g1dzdkc05xdlFPUHlYdGhJa3Nlcy1yNW1FIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAALg","signature":"MEYCIQDKaYmqJhF2PahR6SZmWj8ZFod2ccs5AyMztFb59Iab7wIhAKoJhwJLalZqwYnvpWIFbZCHlSk_fQc2wYj0Pex75JR3","userHandle":null},"clientExtensionResults":{}},"sessionToken":null}

    public static String buildCredentialJson(String type, String pkId, String challenge, String origin, String signature, String clientDataJSON, String authenticatorData, String userHandle, String clientExtensionResults, String rawId) {
        return new JSONObject()
                /*.put("_clientDataJson", new JSONObject()
                        .put("challenge", challenge)
                        .put("origin", origin)
                        .put("type", "webauthn.get"))*/
                .put("clientExtensionResults", new JSONObject())
                .put("response", new JSONObject()
                        .put("clientDataJSON", clientDataJSON)
                        .put("authenticatorData", authenticatorData)
                        .put("signature", signature)
                        .put("userHandle", userHandle))
                .put("id", pkId)
                .put("rawId", rawId)
                .put("type", type).toString();
    }

    public static String buildClientDataJson(String type, String challenge, String origin, String... args) { // TODO: args = crossOrigin oder tokenBinding;
        String clientDataJson = new JSONObject()
                .put("type", type)
                .put("challenge", challenge)
                .put("origin", origin)
                .toString();

        ByteArray byteArray = new ByteArray(clientDataJson.getBytes());
        return byteArray.getBase64().substring(0, byteArray.getBase64().length() - 2);
    }

    public static String buildAuthenticatorData(String rpIdHash, String flags, String signCount, String credentialData, Optional<String> extensions) {
        JSONObject mock_flags = new JSONObject();
        mock_flags.put("value", 5);
        mock_flags.put("UP", true);
        mock_flags.put("UV", true);
        mock_flags.put("BE", false);
        mock_flags.put("BS", false);
        mock_flags.put("AT", false);
        mock_flags.put("ED", false);

        System.out.println("credential data aaguid: " + credentialData);

        String authenticatorDataJson = new JSONObject()
                .put("rpIdHash", rpIdHash)
                .put("flags", mock_flags)
                .put("signCount", signCount)
                .put("credentialData", credentialData)
                .put("extensions", extensions)
                .toString();

        System.out.println(authenticatorDataJson);
        ByteArray byteArray = new ByteArray(authenticatorDataJson.getBytes());
        return byteArray.getBase64().substring(0, byteArray.getBase64().length() - 2);
    }
}

// FINISH AUTH {"requestId":"ECwwMcd_PGpRCWkALZ-J5SVTuOsY9j0cFFcPB-aHaMg","credential":{"type":"public-key","id":"sTh97bcSionEuwwFJu0Knm4sR6aBU8fqs9ZvWeAimVYqyki7KIEuThQ_iAl7wakjaB-84NZ3Fxq6GTda03y8nA","rawId":"sTh97bcSionEuwwFJu0Knm4sR6aBU8fqs9ZvWeAimVYqyki7KIEuThQ_iAl7wakjaB-84NZ3Fxq6GTda03y8nA",
// "response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJMYU9mZjREWGwxaGlaU0xWeWE2aktrazB6LVVFZVVzLW5jbUJNUHpldDNvIiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAACA","signature":"MEYCIQDhvSz88lasxeotNscf-uiwrG4YIg7lL1Oc1SgwkiuqowIhAJlyBkUod_bVsoYVPiCWBRNP3XDUltDxTpDJShNNQ0lW","userHandle":null},"clientExtensionResults":{}},"sessionToken":"4KuIdHvbEFb7711iY6qtduu4qR7HRjVl859G3S-hmGM"}


// FINISH AUTH {"requestId":"gznBdEgJxENCoHeY91BHUavX2pICsMvG4mL0zKLlOI8","credential":{"rawId":"sTh97bcSionEuwwFJu0Knm4sR6aBU8fqs9ZvWeAimVYqyki7KIEuThQ_iAl7wakjaB-84NZ3Fxq6GTda03y8nA","id":"sTh97bcSionEuwwFJu0Knm4sR6aBU8fqs9ZvWeAimVYqyki7KIEuThQ_iAl7wakjaB-84NZ3Fxq6GTda03y8nA","type":"public-key",
// "response":{"userHandle":"","clientDataJSON":"eyJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY2hhbGxlbmdlIjoiTzd0VmNLVDhId3l0WmJ4OGpPdW5JUTdGeFRTdTc3czA2amRjTW50eTVBMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ==","signature":"MEQCIApooHb1tSdHk7Kyg3-3o_9n8fqeejPrR7nJfpItKN_ZAiBta-c_c570mlJjLy_JB9uM9VPXjOfsosGl3-u-CzfnCA","authenticatorData":"eyJycElkSGFzaCI6IlNaWU41WWdPakdoME5CY1BaSFpnVzRfa3JybWloakxIbVZ6enVvTWRsMk0iLCJleHRlbnNpb25zIjoiT3B0aW9uYWwuZW1wdHkiLCJzaWduQ291bnQiOiIyIiwiZmxhZ3MiOiIxIiwiY3JlZGVudGlhbERhdGEiOiJPcHRpb25hbC5lbXB0eSJ9"},"clientExtensionResults":{}},"sessionToken":"Optional.empty"}

// {"requestId":"aQrrBhRMHxiS3scbJpGSwnXHEUkRXgjMaa0SiW54I0k","credential":{"type":"public-key","id":"_hDiWQdks8UqEv6jFwawAUrbkzMhHOnBaivnSvIYSElE4aUSW0r5c7UTw0ewiABmAhDaPmBJSemFUcdnujaBSg","rawId":"_hDiWQdks8UqEv6jFwawAUrbkzMhHOnBaivnSvIYSElE4aUSW0r5c7UTw0ewiABmAhDaPmBJSemFUcdnujaBSg","response":{"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJheF80ZjZxMFkyRGNzcG9jaTE0V0ROZ3IxdE93ZXYySThtZzNEQW1BZkg4Iiwib3JpZ2luIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0MyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ","authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAFg","signature":"MEQCIFyFlRPBSGd3z4nzdFdbA4lSxwQVGGkxIHCiNzotfKxnAiBBrJoyby696BAeMPVE1IGbZzlgVPLW9w32mqGWIHhaxg","userHandle":null},"clientExtensionResults":{}},"sessionToken":"VWSnZEHn6SwGe6j-Sq_H4KRLJS6sv2Ds43RHXBspsm8"}