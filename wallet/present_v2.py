import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.request import urlopen, Request

ROOT = Path(__file__).resolve().parents[1]
WALLET_DATA = ROOT / "wallet_data"
BUNDLE_V2 = WALLET_DATA / "credential_bundle_v2.json"
OUT_PRES_V2 = WALLET_DATA / "last_presentation_v2.json"

VERIFIER_BASE = "http://127.0.0.1:5002"

def http_get_json(url: str) -> dict:
    with urlopen(url) as resp:
        return json.loads(resp.read().decode("utf-8"))

def http_post_json(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

def load_wallet_secret() -> bytes:
    secret_path = WALLET_DATA / "wallet_secret.bin"
    if not secret_path.exists():
        raise FileNotFoundError(
            f"Missing {secret_path}. "
            f"Create it or point this function at existing Tier 1 wallet secret."
        )
    return secret_path.read_bytes()

def pairwise_nym(domain: str, secret: bytes) -> str:
    """
    Domain-specific pseudonym. Keep identical to Tier 1
    Here: HMAC-SHA256(secret, domain) base64url.
    """
    import hmac
    import hashlib
    digest = hmac.new(secret, domain.encode("utf-8"), hashlib.sha256).digest()
    return digest.hex()  # hex is fine; stable and readable

def run_bbs_prove(bundle_path: Path, reveal_csv: str, context_str: str) -> dict:
    """
    Calls Node CLI tool to produce proof JSON.
    """
    cmd = [
        "node",
        str(ROOT / "verifier" / "bbs_tool.js"),
        "prove",
        str(bundle_path),
        reveal_csv,
        context_str,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"bbs_tool prove failed:\nSTDOUT:\n{p.stdout}\nSTDERR:\n{p.stderr}")
    # bbs_tool prints JSON to stdout
    return json.loads(p.stdout)

def main():
    # --- inputs ---
    policy_id = sys.argv[1] if len(sys.argv) > 1 else "age_over_18"
    domain = sys.argv[2] if len(sys.argv) > 2 else "example.com"

    # reveal indices for Tier 2 schema:
    # 1 age_group, 2 assurance_level, 4 expiry
    reveal_csv = "1,2,4"

    if not BUNDLE_V2.exists():
        raise FileNotFoundError(
            f"Missing {BUNDLE_V2}. "
            f"Create it via: node verifier/bbs_tool.js sign examples/cred_for_bbs.json > wallet_data/credential_bundle_v2.json"
        )

    # --- 1) get challenge nonce from verifier ---
    challenge = http_get_json(f"{VERIFIER_BASE}/challenge?policy_id={policy_id}&domain={domain}")
    if "nonce" not in challenge:
        raise RuntimeError(f"Challenge response missing nonce: {challenge}")

    nonce = challenge["nonce"]
    

    # --- 2) generate proof bound to nonce ---
    proof_obj = run_bbs_prove(BUNDLE_V2, reveal_csv, nonce)

    # --- 3) build Tier 2 presentation ---
    secret = load_wallet_secret()
    pres = {
        "version": "v2",
        "domain": domain,
        "policy_id": policy_id,
        "nonce": nonce,
        "pairwise_nym": pairwise_nym(domain, secret),

        # carry proof fields straight through
        "issuer_bbs_pubkey": proof_obj["issuer_bbs_pubkey"],
        "revealed_indices": proof_obj["revealed_indices"],
        "revealed_messages_by_index": proof_obj["revealed_messages_by_index"],
        "bbs_proof": proof_obj["bbs_proof"],

        # pragmatic revocation
        "revocation_handle": proof_obj["revocation_handle"],
    }

    OUT_PRES_V2.write_text(json.dumps(pres, indent=2), encoding="utf-8")
    print(f"Wrote {OUT_PRES_V2}")

    # Optional: auto-submit to verifier
    if os.environ.get("SUBMIT", "") == "1":
        resp = http_post_json(f"{VERIFIER_BASE}/verify_v2", pres)
        print(json.dumps(resp, indent=2))

if __name__ == "__main__":
    main()
