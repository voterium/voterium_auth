use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub hashed_password: String,
    pub user_salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub salt: String,
}

#[derive(Clone)]
pub struct AppState {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
}
