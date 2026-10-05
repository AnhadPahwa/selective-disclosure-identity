from crypto.canonical import canonicalize
from crypto.encoding import b64url_decode
from crypto.signing import ed25519_verify
from crypto.keys import load_issuer_pk
import json

with open("examples/artefacts/issued_credential.json", "r") as f:
    data = json.load(f)

credential = data["credential"]
issuer_sig = data["issuer_sig"]

pk = load_issuer_pk()

ok = ed25519_verify(
    canonicalize(credential),
    b64url_decode(issuer_sig),
    pk
)

print("Issuer signature valid:", ok)
