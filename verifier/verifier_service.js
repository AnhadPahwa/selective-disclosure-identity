const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "2mb" }));

const bbs = require("@mattrglobal/node-bbs-signatures");

function b64urlToU8(s) {
  return Uint8Array.from(Buffer.from(s, "base64url"));
}
function bbsNonceFromContext(contextStr) {
  return Uint8Array.from(
    crypto.createHash("sha256").update(Buffer.from(contextStr, "utf-8")).digest()
  );
}

// -------------------- config --------------------
const ISSUER_PUBKEY_PEM_PATH = "issuer_data/issuer_pk.pem"; 
const NONCE_TTL_MS = 120 * 1000;

// In-memory nonce store: nonce -> issued_at_ms
const nonceStore = new Map();

// Revocation cache
const { isRevoked } = require("./revocation_cache");

// -------------------- helpers --------------------
function b64urlToBuf(s) {
  // supports base64url without padding
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(s + pad, "base64");
}

function sha256Buf(buf) {
  return crypto.createHash("sha256").update(buf).digest();
}

// Deterministic canonical JSON like Python: sort keys, no whitespace.
// Only works for objects composed of JSON primitives/arrays/objects.
function canonicalize(obj) {
  function sortObj(x) {
    if (Array.isArray(x)) return x.map(sortObj);
    if (x && typeof x === "object") {
      const out = {};
      for (const k of Object.keys(x).sort()) out[k] = sortObj(x[k]);
      return out;
    }
    return x;
  }
  return Buffer.from(JSON.stringify(sortObj(obj)));
}

// Extract PEM from base64url-wrapped PEM bytes (wallet_pubkey_b64() encoding)
function walletPemFromB64url(b64urlPem) {
  return b64urlToBuf(b64urlPem).toString("utf-8");
}

// -------------------- policy --------------------
function policySatisfied(policy_id, credentialClaims) {
  const age = credentialClaims.age_group; // "18+", "16-17", etc.
  const assurance = credentialClaims.assurance_level;
  const jurisdiction = credentialClaims.jurisdiction;

  switch (policy_id) {
    case "age_over_18":
      return age === "18+";
    case "age_over_16":
      return age === "16-17" || age === "18+";
    case "high_assurance_only":
      return assurance === "high";
    case "gb_only":
      return jurisdiction === "GB";
    default:
      return false;
  }
}

// -------------------- endpoints --------------------
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/challenge", (req, res) => {
  const policy_id = req.query.policy_id || "age_over_18";
  const nonce = crypto.randomBytes(16).toString("base64url");
  nonceStore.set(nonce, Date.now());

  res.json({
    domain: "example.com",
    policy_id,
    nonce,
    issued_at: new Date().toISOString(),
    expires_in_seconds: NONCE_TTL_MS / 1000,
  });
});

app.post("/verify", (req, res) => {
  try {
    const pres = req.body;

    // Basic shape validation
    const requiredTop = ["domain", "policy_id", "nonce", "disclosed", "hidden_commitments", "bindings", "attached", "wallet_sig"];
    for (const k of requiredTop) {
      if (!(k in pres)) {
        return res.status(400).json({ accepted: false, reason: "MALFORMED", missing: k });
      }
    }

    // 1) Nonce freshness + single use
    const issuedAt = nonceStore.get(pres.nonce);
    if (!issuedAt) {
      return res.json({ accepted: false, reason: "NONCE_INVALID", checks: { nonce_fresh: false } });
    }
    const ageMs = Date.now() - issuedAt;
    if (ageMs > NONCE_TTL_MS) {
      nonceStore.delete(pres.nonce);
      return res.json({ accepted: false, reason: "NONCE_EXPIRED", checks: { nonce_fresh: false } });
    }
    // consume nonce to prevent replay
    nonceStore.delete(pres.nonce);

    // 2) Verify issuer signature on attached credential
    const credential = pres.attached.credential;
    const issuerSigB64url = pres.attached.issuer_sig;
    if (!credential || !issuerSigB64url) {
      return res.status(400).json({ accepted: false, reason: "MALFORMED", missing: "attached.credential/issuer_sig" });
    }

    // issuer public key: load from file produced by python (issuer_data/issuer_pk.pem)
    // Verify for Ed25519
    const fs = require("fs");
    const issuerPubPem = fs.readFileSync("issuer_data/issuer_pk.pem", "utf-8");

    const credBytes = canonicalize(credential);
    const issuerSig = b64urlToBuf(issuerSigB64url);

    const issuerOk = crypto.verify(null, credBytes, issuerPubPem, issuerSig);
    if (!issuerOk) {
      return res.json({ accepted: false, reason: "SIG_INVALID", checks: { sig_valid: false } });
    }

    // 3) Recompute digest and compare to provided digest
    const digestObj = {
      version: "v1",
      domain: pres.domain,
      policy_id: pres.policy_id,
      nonce: pres.nonce,
      disclosed: pres.disclosed,
      hidden_commitments: pres.hidden_commitments,
    };
    const digest = sha256Buf(canonicalize(digestObj)); // bytes
    const digestB64url = digest.toString("base64url");
    const claimedDigest = pres.bindings.presentation_digest;

    if (digestB64url !== claimedDigest) {
      return res.json({ accepted: false, reason: "DIGEST_MISMATCH", checks: { digest_match: false } });
    }

    // 4) Verify wallet signature over digest using subject_pubkey in credential
    const walletSig = b64urlToBuf(pres.wallet_sig);
    const walletPem = walletPemFromB64url(credential.subject_pubkey);

    const walletOk = crypto.verify(null, digest, walletPem, walletSig);
    if (!walletOk) {
      return res.json({ accepted: false, reason: "WALLET_SIG_INVALID", checks: { wallet_sig_valid: false } });
    }

    // 5) Revocation check 
    if (isRevoked(credential.revocation_handle)) {
        return res.json({ accepted: false, reason: "REVOKED", checks: { revoked: true } });
    }

    // 6) Policy check
    const okPolicy = policySatisfied(pres.policy_id, credential.claims);
    if (!okPolicy) {
      return res.json({ accepted: false, reason: "POLICY_FAIL", checks: { policy_satisfied: false } });
    }

    return res.json({
      accepted: true,
      reason: "OK",
      checks: {
        nonce_fresh: true,
        sig_valid: true,
        digest_match: true,
        wallet_sig_valid: true,
        not_revoked: true,
        policy_satisfied: true,
      },
    });
  } catch (e) {
    return res.status(500).json({ accepted: false, reason: "SERVER_ERROR", error: String(e) });
  }
});

app.post("/verify_v2", async (req, res) => {
  try {
    const pres = req.body;

    // basic shape validation (Tier 2)
    const requiredTop = [
      "version",
      "domain",
      "policy_id",
      "nonce",
      "pairwise_nym",
      "issuer_bbs_pubkey",
      "revealed_indices",
      "revealed_messages_by_index",
      "bbs_proof",
      "revocation_handle",
    ];
    for (const k of requiredTop) {
      if (!(k in pres)) {
        return res.status(400).json({ accepted: false, reason: "MALFORMED", missing: k });
      }
    }
    if (pres.version !== "v2") {
      return res.status(400).json({ accepted: false, reason: "MALFORMED", missing: "version=v2" });
    }

    const checks = {};

    // 1) Nonce freshness + single-use
    const issuedAt = nonceStore.get(pres.nonce);
    if (!issuedAt) {
      return res.json({ accepted: false, reason: "NONCE_INVALID", checks: { nonce_fresh: false } });
    }
    const ageMs = Date.now() - issuedAt;
    if (ageMs > NONCE_TTL_MS) {
      nonceStore.delete(pres.nonce);
      return res.json({ accepted: false, reason: "NONCE_EXPIRED", checks: { nonce_fresh: false } });
    }
    nonceStore.delete(pres.nonce);
    checks.nonce_fresh = true;

    // 2) Verify BBS+ proof (replaces issuer signature on attached credential)
    // bbs_tool.js stores issuer_bbs_pubkey.publicKey as base64url string
    const pubKeyU8 = b64urlToU8(pres.issuer_bbs_pubkey.publicKey);
    const proofU8 = b64urlToU8(pres.bbs_proof);

    // proof is bound to sha256(must match bbs_tool.js)
    const nonceU8 = bbsNonceFromContext(pres.nonce);

    // revealed_messages must be in the same order as revealed_indices
    const revealed = pres.revealed_indices;
    const revealedMessages = revealed.map((i) => {
      const v =
        pres.revealed_messages_by_index[String(i)] ??
        pres.revealed_messages_by_index[i];
      return Uint8Array.from(Buffer.from(String(v ?? ""), "utf-8"));
    });

    const okObj = await bbs.blsVerifyProof({
      publicKey: pubKeyU8,
      proof: proofU8,
      revealed,
      messages: revealedMessages,
      nonce: nonceU8,
    });

    const proofOk =
      okObj === true ||
      okObj?.verified === true ||
      okObj?.ok === true ||
      okObj?.ok?.verified === true;

    if (!proofOk) {
      return res.json({ accepted: false, reason: "PROOF_INVALID", checks: { ...checks, sig_valid: false } });
    }
    checks.sig_valid = true;

    // 3) Revocation check 
    if (isRevoked(pres.revocation_handle)) {
      return res.json({ accepted: false, reason: "REVOKED", checks: { ...checks, not_revoked: false } });
    }
    checks.not_revoked = true;

    // 4) Policy check 
    // Schema indices:
    // 1 age_group, 2 assurance_level, 3 jurisdiction, 4 expiry
    const age_group = pres.revealed_messages_by_index["1"] ?? pres.revealed_messages_by_index[1];
    const assurance_level = pres.revealed_messages_by_index["2"] ?? pres.revealed_messages_by_index[2];
    const jurisdiction = pres.revealed_messages_by_index["3"] ?? pres.revealed_messages_by_index[3];
    const expiry = pres.revealed_messages_by_index["4"] ?? pres.revealed_messages_by_index[4];

    // Build a claims object shaped like Tier 1
    const claimsForPolicy = {
      age_group,
      assurance_level,
      jurisdiction,
      expiry,
    };

    const okPolicy = policySatisfied(pres.policy_id, claimsForPolicy);
    if (!okPolicy) {
      return res.json({ accepted: false, reason: "POLICY_FAIL", checks: { ...checks, policy_satisfied: false } });
    }
    checks.policy_satisfied = true;

    return res.json({ accepted: true, reason: "OK", checks });
  } catch (e) {
    return res.status(500).json({ accepted: false, reason: "SERVER_ERROR", error: String(e) });
  }
});

app.listen(5002, "127.0.0.1", () => {
  console.log("Verifier listening on http://127.0.0.1:5002");
});
