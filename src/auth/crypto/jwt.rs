use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::AppError;

type HmacSha256 = Hmac<Sha256>;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub sub: String, // user UUID as a string
    pub exp: i64,    // Unix timestamp
    pub iat: i64,    // Unix timestamp
    pub username: String,
    pub is_admin: bool,
}
pub fn create_token(
    secret: &str,
    user_id: uuid::Uuid,
    username: &str,
    is_admin: bool,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp();
    let exp = now + 7 * 24 * 60 * 60; // 7 days in seconds
    let claims = Claims {
        sub: user_id.to_string(),
        exp,
        iat: now,
        username: username.to_owned(),
        is_admin,
    };
    let header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_json = serde_json::to_string(&claims)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("serialize claims: {e}")))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}

pub fn verify_token(secret: &str, token: &str) -> Result<Claims, AppError> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(AppError::Unauthorized);
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let expected_sig = hmac_sha256(secret.as_bytes(), signing_input.as_bytes());
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| AppError::Unauthorized)?;

    let sig_valid: bool = expected_sig.ct_eq(&provided_sig).into();
    if !sig_valid {
        return Err(AppError::Unauthorized);
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| AppError::Unauthorized)?;
    let payload_str = std::str::from_utf8(&payload_bytes).map_err(|_| AppError::Unauthorized)?;
    let claims: Claims = serde_json::from_str(payload_str).map_err(|_| AppError::Unauthorized)?;
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(AppError::Unauthorized);
    }

    Ok(claims)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any non-empty key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const TEST_SECRET: &str = "test-secret-do-not-use-in-prod";

    fn test_user() -> Uuid {
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    #[test]
    fn roundtrip_valid_token() {
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

    #[test]
    fn rejects_tampered_signature() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        assert_eq!(parts.len(), 3);
        let mut sig = parts[2].to_string();
        let last = sig.pop().unwrap();
        let flipped = if last == 'a' { 'b' } else { 'a' };
        sig.push(flipped);
        let tampered = format!("{}.{}.{}", parts[0], parts[1], sig);
        assert!(verify_token(TEST_SECRET, &tampered).is_err());
    }

    #[test]
    fn rejects_wrong_secret() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();
        assert!(verify_token("wrong-secret", &token).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let token = create_token(TEST_SECRET, test_user(), "river", false).unwrap();
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        payload["is_admin"] = serde_json::json!(true);
        let new_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).unwrap().as_bytes());
        let forged = format!("{}.{}.{}", parts[0], new_payload, parts[2]);
        assert!(verify_token(TEST_SECRET, &forged).is_err());
    }

    #[test]
    fn rejects_malformed_token() {
        assert!(verify_token(TEST_SECRET, "not.a.valid.jwt.at.all").is_err());
        assert!(verify_token(TEST_SECRET, "onlytwoparts.here").is_err());
        assert!(verify_token(TEST_SECRET, "").is_err());
    }

    #[test]
    fn hmac_is_deterministic() {
        let a = hmac_sha256(b"secret", b"data");
        let b = hmac_sha256(b"secret", b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_different_keys_differ() {
        assert_ne!(hmac_sha256(b"key1", b"data"), hmac_sha256(b"key2", b"data"));
    }

    #[test]
    fn hmac_different_data_differ() {
        assert_ne!(hmac_sha256(b"key", b"data1"), hmac_sha256(b"key", b"data2"));
    }
}
