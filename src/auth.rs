use crate::models::Claims;
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use std::{env, fs};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

pub fn gen_random_b64_string(length: usize) -> String {
    let mut random_bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut random_bytes);
    URL_SAFE_NO_PAD.encode(&random_bytes)
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let algo = Argon2::default();
    let password_hash = algo
        .hash_password(password.as_bytes(), &salt)
        .context("Failed to hash password")?;
    Ok(password_hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash).context("Failed to parse password hash")?;
    let algo = Argon2::default();
    match algo.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false), // Incorrect password
        Err(e) => Err(e).context("Failed to verify password"),
    }
}

pub fn load_key_pair() -> (EncodingKey, DecodingKey) {
    let private_key_path = env::var("JWT_PRIVATE_KEY_PATH").unwrap_or("key.pem".to_owned());
    let private_key = fs::read(&private_key_path)
        .expect(&format!("Failed to read private key {}", &private_key_path));
    let encoding_key = EncodingKey::from_ed_pem(&private_key)
        .expect(&format!("Invalid private key {}", private_key_path));

    let public_key_path = env::var("JWT_PUBLIC_KEY_PATH").unwrap_or("key.pub".to_owned());
    let public_key = fs::read(&public_key_path)
        .expect(&format!("Failed to read public key {}", &public_key_path));
    let decoding_key = DecodingKey::from_ed_pem(&public_key)
        .expect(&format!("Invalid public key {}", public_key_path));

    (encoding_key, decoding_key)
}

pub fn create_jwt(user_id: &str, user_salt: &str, encoding_key: &EncodingKey) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(3600))
        .expect("Valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
        salt: user_salt.to_owned(),
    };

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, encoding_key)
        .context("Failed to create JWT")?;
    Ok(token)
}

pub fn generate_refresh_token() -> String {
    let mut random_bytes = [0u8; 32]; // 256 bits
    OsRng.fill_bytes(&mut random_bytes);
    URL_SAFE_NO_PAD.encode(&random_bytes)
}
