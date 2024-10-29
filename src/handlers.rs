use actix_web::{post, web, HttpResponse, Responder};
use serde::{Serialize, Deserialize};
use sqlx::SqlitePool;
use uuid::Uuid;
use crate::auth::{hash_password, verify_password, create_jwt, generate_refresh_token};
use crate::models::{NewUser, User, UserResponse};
use chrono::{Utc, Duration};

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
            eprintln!("Password hashing error: {}", err);
            return HttpResponse::InternalServerError().finish();
        },
    };

    let user = User {
        id: Uuid::new_v4().to_string(),
        email: new_user.email.clone(),
        hashed_password,
    };

    let result = sqlx::query("INSERT INTO users (id, email, hashed_password) VALUES (?, ?, ?)")
        .bind(&user.id)
        .bind(&user.email)
        .bind(&user.hashed_password)
        .execute(pool.get_ref())
        .await;

    match result {
        Ok(_) => {
            let user_response = UserResponse {
                id: user.id,
                email: user.email,
            };
            HttpResponse::Ok().json(user_response)
        }
        Err(err) => {
            eprintln!("Database insertion error: {}", err);
            HttpResponse::InternalServerError().finish()
        },
    }
}

#[post("/login")]
async fn login_user(
    credentials: web::Json<NewUser>,
    pool: web::Data<SqlitePool>,
) -> impl Responder {
    let result = sqlx::query_as::<_, (String, String)>(
        "SELECT id, hashed_password FROM users WHERE email = ?"
    )
    .bind(&credentials.email)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok((user_id, stored_hash)) => {
            match verify_password(&stored_hash, &credentials.password) {
                Ok(true) => {
                    let access_token = match create_jwt(&user_id) {
                        Ok(token) => token,
                        Err(err) => {
                            eprintln!("JWT creation error: {}", err);
                            return HttpResponse::InternalServerError().finish();
                        },
                    };

                    let refresh_token = generate_refresh_token();
                    let expires_at = Utc::now()
                        .checked_add_signed(Duration::days(30))
                        .expect("Valid timestamp")
                        .timestamp();

                    // Store refresh token in the database
                    if let Err(err) = sqlx::query(
                        "INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)"
                    )
                    .bind(&refresh_token)
                    .bind(&user_id)
                    .bind(expires_at)
                    .execute(pool.get_ref())
                    .await
                    {
                        eprintln!("Database insertion error: {}", err);
                        return HttpResponse::InternalServerError().finish();
                    }

                    let response = LoginResponse {
                        access_token,
                        refresh_token,
                    };

                    HttpResponse::Ok().json(response)
                }
                Ok(false) => HttpResponse::Unauthorized().body("Invalid credentials"),
                Err(err) => {
                    eprintln!("Password verification error: {}", err);
                    HttpResponse::InternalServerError().finish()
                },
            }
        }
        Err(err) => {
            eprintln!("Database query error: {}", err);
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
    let result = sqlx::query_as::<_, (String, i64)>(
        "SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?"
    )
    .bind(&refresh_req.refresh_token)
    .fetch_one(pool.get_ref())
    .await;

    match result {
        Ok((user_id, expires_at)) => {
            if Utc::now().timestamp() > expires_at {
                // Token has expired
                return HttpResponse::Unauthorized().body("Refresh token expired");
            }

            // Generate new access token
            let access_token = match create_jwt(&user_id) {
                Ok(token) => token,
                Err(err) => {
                    eprintln!("JWT creation error: {}", err);
                    return HttpResponse::InternalServerError().finish();
                },
            };

            HttpResponse::Ok().json(LoginResponse {
                access_token,
                refresh_token: refresh_req.refresh_token.clone(), // Reuse the same refresh token
            })
        }
        Err(err) => {
            eprintln!("Database query error: {}", err);
            HttpResponse::Unauthorized().body("Invalid refresh token")
        },
    }
}
