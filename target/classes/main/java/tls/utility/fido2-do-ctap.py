from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient, UserInteraction
from fido2.server import Fido2Server
from getpass import getpass
import sys
import ctypes
from fido2.webauthn import PublicKeyCredentialType
import json
from fido2.utils import websafe_encode, websafe_decode
import base64


# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return "1234"

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


uv = "discouraged"

if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    # Use the Windows WebAuthn API if available, and we're not running as admin
    client = WindowsClient("https://example.com")
else:
    # Locate a device
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is not None:
        print("Use USB HID channel.")
    else:
        try:
            from fido2.pcsc import CtapPcscDevice

            dev = next(CtapPcscDevice.list_devices(), None)
            print("Use NFC channel.")
        except Exception as e:
            print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # Set up a FIDO 2 client using the origin https://example.com
    client = Fido2Client(dev, "https://localhost:8443", user_interaction=CliInteraction())

    # Prefer UV if supported and configured
    #if client.info.options.get("uv") or client.info.options.get("pinUvAuthToken"):
    #   uv = "preferred"
    #  print("Authenticator supports User Verification")

server = Fido2Server({"id": "localhost", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "A. User"}


# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user, user_verification=uv, authenticator_attachment="cross-platform"
)

# Create a credential
result = client.make_credential(create_options["publicKey"])

# Complete registration
auth_data = server.register_complete(
    state, result.client_data, result.attestation_object
)
credentials = [auth_data.credential_data]

# Prepare parameters for getAssertion
publicKeyRequestOptions = sys.argv[1]
publicKeyRequestOptions = publicKeyRequestOptions.replace("*", "\"")
regCredJSON = json.loads(publicKeyRequestOptions)
challenge = regCredJSON["challenge"]
rpId = regCredJSON["rpId"]
regCredJSON["challenge"] = websafe_decode(regCredJSON["challenge"])
regCredJSON["allowCredentials"][0]["id"] = websafe_decode(regCredJSON["allowCredentials"][0]["id"])
del regCredJSON["extensions"]
regCredJSON["userVerification"] = uv
regCredJSON["allowCredentials"][0]["type"] = PublicKeyCredentialType.PUBLIC_KEY

# Authenticate the credential
result = client.get_assertion(regCredJSON)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

assert challenge == websafe_encode(result.client_data.challenge)

print("CLIENTDATA " + str(result.client_data))
print("AUTHDATA " + str(result.authenticator_data))
print("SIGNATURE " + websafe_encode(result.signature))
print("RPIDHASH " + websafe_encode(result.authenticator_data.rp_id_hash))
print("COUNTER " + str(result.authenticator_data.counter))
print("FLAGS " + str(result.authenticator_data.flags))
print("CREDENTIALDATA " + websafe_encode(auth_data.credential_data))