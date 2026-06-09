// jwt.rs — JSON Web Token implementation from scratch.
//
// A JWT proves "I am who I say I am" without the server storing sessions.
// The server signs a payload with a secret key. On future requests, it
// re-signs the received payload and checks the signatures match — if they
// do, the payload was definitely created by this server and hasn't been
// tampered with.
//
// ┌─────────────────────────────────────────────────────────────┐
// │ JWT structure:                                               │
// │   base64url(HEADER) . base64url(PAYLOAD) . base64url(SIG)   │
// │                                                             │
// │ HEADER:  {"alg":"HS256","typ":"JWT"}                        │
// │ PAYLOAD: {"sub":"<uuid>","exp":1234567890,...}               │
// │ SIG:     HMAC-SHA256(header + "." + payload, secret)        │
// └─────────────────────────────────────────────────────────────┘
//
// HMAC (Hash-based Message Authentication Code):
//   HMAC(key, msg) = SHA256((key XOR opad) || SHA256((key XOR ipad) || msg))
//   The double-hashing construction prevents length-extension attacks.
//   We use the `hmac` crate which implements this correctly.
//
// base64url vs base64:
//   Standard base64 uses '+', '/', and '=' which are not URL-safe.
//   base64url replaces '+' with '-', '/' with '_', and drops '=' padding.
//   JWTs go in HTTP headers and URLs, so they must use base64url.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

// Type alias: Hmac<Sha256> is verbose; HmacSha256 is cleaner.
// This is not a new type — just a shorthand.
type HmacSha256 = Hmac<Sha256>;

// Claims is the "payload" section of the JWT — the data we want to carry.
//
// We use serde here only for JSON serialization/deserialization of the payload.
// This is different from the jsonwebtoken crate, which handled the entire
// JWT lifecycle. We're just using serde to turn a struct into a JSON string.
//
// Fields we store (all denormalized so middleware never needs a DB round-trip):
//   sub      — "subject": the user's UUID (standard JWT claim, RFC 7519)
//   exp      — "expiration": Unix timestamp after which the token is invalid
//   iat      — "issued at": Unix timestamp of creation (useful for audit logs)
//   username — copied from DB at login time; avoids a SELECT on each request
//   is_admin — same reasoning; lets AdminUser extractor check without a DB hit
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub sub:      String, // user UUID as a string
    pub exp:      i64,    // Unix timestamp
    pub iat:      i64,    // Unix timestamp
    pub username: String,
    pub is_admin: bool,
}

// ── Token creation ───────────────────────────────────────────────────────────

pub fn create_token(
    secret:   &str,
    user_id:  uuid::Uuid,
    username: &str,
    is_admin: bool,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + 7 * 24 * 60 * 60; // 7 days in seconds

    let claims = Claims {
        sub:      user_id.to_string(),
        exp,
        iat:      now,
        username: username.to_owned(),
        is_admin,
    };

    // ── Step 1: build the header ─────────────────────────────────────────────
    // The header is always the same for HS256 JWTs.
    // "alg" tells verifiers which algorithm was used.
    // "typ" is just a label; "JWT" is conventional.
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());

    // ── Step 2: serialize and encode the payload ─────────────────────────────
    // serde_json::to_string turns our Claims struct into a JSON string.
    // map_err converts serde_json::Error into anyhow::Error, which AppError
    // automatically wraps via its #[from] anyhow::Error variant.
    let payload_json = serde_json::to_string(&claims)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize claims: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // ── Step 3: sign header + payload with HMAC-SHA256 ───────────────────────
    // The signing input is EXACTLY "header_b64.payload_b64".
    // Changing either section would produce a different HMAC, invalidating
    // the token. This is what prevents tampering.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    // ── Step 4: assemble the three sections with dots ────────────────────────
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

// ── Token verification ───────────────────────────────────────────────────────

pub fn verify_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    // ── Step 1: split into exactly 3 sections ───────────────────────────────
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized);
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    // ── Step 2: recompute the expected signature ─────────────────────────────
    // We sign the same "header.payload" string using our secret.
    // If the token came from us, this should match the provided signature.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());

    // Decode the signature the client sent us.
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AppError::Unauthorized)?;

    // ── Step 3: constant-time signature comparison ───────────────────────────
    //
    // WHY NOT just `expected_sig == provided_sig`?
    //
    // A naive equality check returns false as soon as it finds the first
    // differing byte. An attacker can measure tiny differences in response
    // time (microseconds) to learn how many bytes of their forged signature
    // are correct. Given enough requests, they can reconstruct a valid
    // signature without ever knowing the secret key. This is a "timing attack".
    //
    // ConstantTimeEq always compares ALL bytes regardless of where the first
    // difference is, so response time gives the attacker zero information.
    //
    // .into() converts subtle::Choice (a 0/1 wrapper) to bool.
    let sig_valid: bool = expected_sig.ct_eq(&provided_sig).into();
    if !sig_valid {
        return Err(AppError::Unauthorized);
    }

    // ── Step 4: decode and parse the payload ────────────────────────────────
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::Unauthorized)?;
    let payload_str = std::str::from_utf8(&payload_bytes)
        .map_err(|_| AppError::Unauthorized)?;
    let claims: Claims = serde_json::from_str(payload_str)
        .map_err(|_| AppError::Unauthorized)?;

    // ── Step 5: check expiry ─────────────────────────────────────────────────
    // exp is a Unix timestamp (seconds since 1970-01-01 00:00:00 UTC).
    // If it's in the past, the token is expired and must be rejected.
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

// ── Internal helper ──────────────────────────────────────────────────────────

// Computes HMAC-SHA256(key, message) and returns the raw bytes.
//
// The hmac crate uses the "typestate" pattern: you build up a Mac object,
// feed it data with update(), then finalize() consumes it and returns the tag.
// This prevents accidentally reusing a partially-updated MAC state.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    // new_from_slice accepts any key length (HMAC pads/hashes long keys internally).
    // The only error case is a zero-length key; we panic here because that would
    // be a programming error (JWT_SECRET is validated at startup).
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any non-empty key length");
    mac.update(message);
    // finalize() returns a CtOutput<HmacSha256>; into_bytes() extracts the raw
    // GenericArray<u8, 32>. We collect into Vec<u8> for easier handling.
    mac.finalize().into_bytes().to_vec()
}
