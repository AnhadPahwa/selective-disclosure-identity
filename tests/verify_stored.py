from crypto.canonical import canonicalize
from crypto.encoding import b64url_decode
from crypto.keys import load_issuer_pk
from crypto.signing import ed25519_verify
from wallet.storage import load_credential_bundle

def main():
    bundle = load_credential_bundle()
    credential = bundle["credential"]
    issuer_sig = bundle["issuer_sig"]

    pk = load_issuer_pk()
    ok = ed25519_verify(canonicalize(credential), b64url_decode(issuer_sig), pk)
    print("Stored credential issuer signature valid:", ok)

if __name__ == "__main__":
    main()
