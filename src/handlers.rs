use actix_web::{post, web, HttpResponse, Responder};
use serde::{Serialize, Deserialize};
use sqlx::SqlitePool;
use crate::auth::{hash_password, verify_password, create_jwt, generate_refresh_token, gen_random_b64_string};
use crate::models::{NewUser, User, UserResponse};
use chrono::{Utc, Duration};
use log::{error, info, warn};

#[derive(Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[post("/register")]
async fn register_user(
    new_user: web::Json<NewUser>,
    pool: web::Data<SqlitePool>,
) -> impl Responder {
    let hashed_password = match hash_password(&new_user.password) {
        Ok(hash) => hash,
        Err(err) => {
            error!("Password hashing error: {}", err);
            return HttpResponse::InternalServerError().finish();
        },
    };

    let user = User {
        id: gen_random_b64_string(16),
        email: new_user.email.clone(),
        hashed_password,
        user_salt: gen_random_b64_string(8),
    };

    // Insert the new user without refresh_token and refresh_token_expiry
    let result = sqlx::query("INSERT INTO users (id, email, hashed_password, user_salt) VALUES (?, ?, ?, ?)")
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.hashed_password)
        .bind(&user.user_salt)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            info!("New user registered: {}", user.email);
            let user_response = UserResponse {
                id: user.id,
                email: user.email,
            };
            HttpResponse::Ok().json(user_response)
        }
        Err(err) => {
            error!("Database insertion error: {}", err);
            HttpResponse::InternalServerError().finish()
        },
    }
}

#[post("/login")]
async fn login_user(
    credentials: web::Json<NewUser>,
    pool: web::Data<SqlitePool>,
) -> impl Responder {
    let result = sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, hashed_password, user_salt FROM users WHERE email = ?"
    )
    .bind(&credentials.email)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok((user_id, stored_hash, user_salt)) => {
            match verify_password(&stored_hash, &credentials.password) {
                Ok(true) => {
                    let access_token = match create_jwt(&user_id, &user_salt) {
                        Ok(token) => token,
                        Err(err) => {
                            error!("JWT creation error: {}", err);
                            return HttpResponse::InternalServerError().finish();
                        },
                    };

                    let refresh_token = generate_refresh_token();
                    let refresh_token_expiry = Utc::now()
                        .checked_add_signed(Duration::days(30))
                        .expect("Valid timestamp")
                        .timestamp();

                    // Update the user's refresh_token and refresh_token_expiry
                    if let Err(err) = sqlx::query(
                        "UPDATE users SET refresh_token = ?, refresh_token_expiry = ? WHERE id = ?"
                    )
                    .bind(&refresh_token)
                    .bind(refresh_token_expiry)
                    .bind(&user_id)
                    .execute(pool.get_ref())
                    .await
                    {
                        error!("Database update error: {}", err);
                        return HttpResponse::InternalServerError().finish();
                    }

                    info!("User logged in: {}", credentials.email);
                    let response = LoginResponse {
                        access_token,
                        refresh_token,
                    };

                    HttpResponse::Ok().json(response)
                }
                Ok(false) => {
                    warn!("Invalid login attempt for user: {}", credentials.email);
                    HttpResponse::Unauthorized().body("Invalid credentials")
                }
                Err(err) => {
                    error!("Password verification error: {}", err);
                    HttpResponse::InternalServerError().finish()
                },
            }
        }
        Err(err) => {
            error!("Database query error: {}", err);
            HttpResponse::Unauthorized().body("Invalid credentials")
        },
    }
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[post("/refresh")]
async fn refresh_token_handler(
    refresh_req: web::Json<RefreshRequest>,
    pool: web::Data<SqlitePool>,
) -> impl Responder {
    let result = sqlx::query_as::<_, (String, i64, String)>(
        "SELECT id, refresh_token_expiry, user_salt FROM users WHERE refresh_token = ?"
    )
    .bind(&refresh_req.refresh_token)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok((user_id, refresh_token_expiry, user_salt)) => {
            if Utc::now().timestamp() > refresh_token_expiry {
                warn!("Expired refresh token used by user_id: {}", user_id);
                return HttpResponse::Unauthorized().body("Refresh token expired");
            }

            // Generate new access token
            let access_token = match create_jwt(&user_id, &user_salt) {
                Ok(token) => token,
                Err(err) => {
                    error!("JWT creation error: {}", err);
                    return HttpResponse::InternalServerError().finish();
                },
            };

            info!("Access token refreshed for user_id: {}", user_id);
            HttpResponse::Ok().json(LoginResponse {
                access_token,
                refresh_token: refresh_req.refresh_token.clone(), // Reuse the same refresh token
            })
        }
        Err(err) => {
            error!("Database query error: {}", err);
            HttpResponse::Unauthorized().body("Invalid refresh token")
        },
    }
}
