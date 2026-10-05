from crypto.keys import generate_issuer_keypair, load_issuer_sk, load_issuer_pk
from crypto.canonical import canonicalize
from crypto.encoding import b64url_decode
from crypto.signing import ed25519_verify
from issuer.issue import make_credential, sign_credential

def main():
    generate_issuer_keypair()
    sk = load_issuer_sk()
    pk = load_issuer_pk()

    cred = make_credential(
        subject_pubkey_b64="base64url(fake_wallet_pk)",
        claims={"age_group": "18+", "assurance_level": "high", "jurisdiction": "GB"},
        expiry_days=90
    )
    issued = sign_credential(cred, sk)

    ok = ed25519_verify(
        canonicalize(issued.credential),
        b64url_decode(issued.issuer_sig),
        pk
    )
    print("Signature valid:", ok)

if __name__ == "__main__":
    main()