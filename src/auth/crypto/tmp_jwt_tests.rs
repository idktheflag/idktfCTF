// ── INSTRUCTION ───────────────────────────────────────────────────────────────
// This file contains the #[cfg(test)] module for jwt.rs.
// When you retype jwt.rs, append the entire block below to the bottom of the file.
// Delete this file afterward (it's just a retype guide, not a real module).
// ─────────────────────────────────────────────────────────────────────────────

// ── Unit tests ────────────────────────────────────────────────────────────────
//
// #[cfg(test)] means this entire module is compiled only during `cargo test`,
// never in release builds. Test code can be in the same file as the code it's
// testing — Rust's module system makes this idiomatic.
//
// Run with:  cargo test auth::crypto::jwt
//
#[cfg(test)]
mod tests {
    use super::*;           // import everything from jwt.rs into this scope
    use uuid::Uuid;

    // A fixed secret used only in tests. Never reuse in production.
    const TEST_SECRET: &str = "test-secret-do-not-use-in-prod";

    // Helper: a deterministic fake user UUID.
    fn test_user() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    // ── create_token + verify_token round-trip ────────────────────────────────

    #[test]
    fn roundtrip_valid_token() {
        // Create a token, then verify it — the claims should come back intact.
        let token = create_token(TEST_SECRET, test_user(), "river", false)
            .expect("create_token should succeed");

        let claims = verify_token(TEST_SECRET, &token)
            .expect("verify_token should succeed on a fresh token");

        assert_eq!(claims.sub, test_user().to_string());
        assert_eq!(claims.username, "river");
        assert!(!claims.is_admin);
    }

    #[test]
    fn roundtrip_admin_flag() {
        let token = create_token(TEST_SECRET, test_user(), "admin_user", true).unwrap();
        let claims = verify_token(TEST_SECRET, &token).unwrap();
        assert!(claims.is_admin);
    }

    // ── Signature tampering ───────────────────────────────────────────────────
    // A tampered token must be rejected. This proves our HMAC check works.

    #[test]
    fn rejects_tampered_signature() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();

        // Flip the last character of the signature section.
        // JWT structure: "header.payload.signature" — we corrupt the signature.
        let mut parts: Vec<&str> = token.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3, "JWT must have exactly 3 sections");

        let mut sig = parts[2].to_string();
        // XOR the last byte's ASCII value with 1 to change it without making it
        // non-ASCII (which would cause a base64 decode error instead of a sig error).
        let last = sig.pop().unwrap();
        let flipped = if last == 'a' { 'b' } else { 'a' };
        sig.push(flipped);

        let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);

        let result = verify_token(TEST_SECRET, &tampered);
        assert!(result.is_err(), "tampered signature must be rejected");
    }

    #[test]
    fn rejects_wrong_secret() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();
        // Verifying with a different secret must fail — the HMAC will differ.
        let result = verify_token("wrong-secret", &token);
        assert!(result.is_err());
    }

    // ── Payload tampering ─────────────────────────────────────────────────────
    // Changing the payload (e.g. escalating is_admin) must invalidate the sig.

    #[test]
    fn rejects_tampered_payload() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();

        // Decode the payload, flip is_admin, re-encode, reconstruct the token.
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let mut payload: serde_json::Value =
            serde_json::from_slice(&payload_bytes).unwrap();

        // Escalate to admin — this is the attack we're defending against.
        payload["is_admin"] = serde_json::json!(true);

        let new_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&payload).unwrap().as_bytes());

        // The signature is still for the old payload, so it won't match.
        let forged = format!("{}.{}.{}", parts[0], new_payload, parts[2]);

        let result = verify_token(TEST_SECRET, &forged);
        assert!(result.is_err(), "forged payload must be rejected");
    }

    // ── Structure validation ──────────────────────────────────────────────────

    #[test]
    fn rejects_malformed_token() {
        assert!(verify_token(TEST_SECRET, "not.a.valid.jwt.at.all").is_err());
        assert!(verify_token(TEST_SECRET, "onlytwoparts.here").is_err());
        assert!(verify_token(TEST_SECRET, "").is_err());
    }

    // ── HMAC helper ───────────────────────────────────────────────────────────

    #[test]
    fn hmac_is_deterministic() {
        // The same key + data must always produce the same MAC.
        // Non-determinism would be a catastrophic bug (tokens would never verify).
        let a = hmac_sha256(b"secret", b"data");
        let b = hmac_sha256(b"secret", b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_different_keys_produce_different_macs() {
        let a = hmac_sha256(b"key1", b"data");
        let b = hmac_sha256(b"key2", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn hmac_different_data_produce_different_macs() {
        let a = hmac_sha256(b"key", b"data1");
        let b = hmac_sha256(b"key", b"data2");
        assert_ne!(a, b);
    }
}
