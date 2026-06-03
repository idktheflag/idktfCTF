use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use anyhow::Result; 
use chrono;

const SECRET: &str = "tempest is a little whiny bitch";

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn create_token(user_id: &str) -> Result<String> {
    let expiry = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::days(7))
        .unwrap()
        .timestamp() as usize;
    let claims = Claims { sub: user_id.to_string(), exp: expiry };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET.as_bytes()))?;
    Ok(token)
}

pub fn verify_token(token: &str) -> Result<Claims> {
    let data = decode::<Claims>(token, &DecodingKey::from_secret(SECRET.as_bytes()), &Validation::default())?;
    Ok(data.claims)
}
