use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation, TokenData};
use serde::{Serialize, Deserialize};
use std::{env, fs};
use chrono::{Utc, Duration};
use lazy_static::lazy_static;
use anyhow::{Result, Context};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use rand::RngCore;

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

#[derive(Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
}

lazy_static! {
    static ref ENCODING_KEY: EncodingKey = {
        let private_key_path = env::var("JWT_PRIVATE_KEY_PATH").expect("JWT_PRIVATE_KEY_PATH not set");
        let private_key = fs::read(private_key_path).expect("Failed to read private key");
        EncodingKey::from_ed_pem(&private_key).expect("Invalid private key")
    };

    static ref DECODING_KEY: DecodingKey = {
        let public_key_path = env::var("JWT_PUBLIC_KEY_PATH").expect("JWT_PUBLIC_KEY_PATH not set");
        let public_key = fs::read(public_key_path).expect("Failed to read public key");
        DecodingKey::from_ed_pem(&public_key).expect("Invalid public key")
    };
}

pub fn create_jwt(user_id: &str) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(3600))
        .expect("Valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, &ENCODING_KEY)
        .context("Failed to create JWT")?;
    Ok(token)
}

pub fn verify_jwt(token: &str) -> Result<TokenData<Claims>> {
    let validation = Validation::new(Algorithm::EdDSA);
    let token_data = decode::<Claims>(token, &DECODING_KEY, &validation)
        .context("Failed to verify JWT")?;
    Ok(token_data)
}

pub fn generate_refresh_token() -> String {
    let mut random_bytes = [0u8; 32]; // 256 bits
    OsRng.fill_bytes(&mut random_bytes);
    STANDARD_NO_PAD.encode(&random_bytes)
}