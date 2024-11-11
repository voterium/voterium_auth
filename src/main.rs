use actix_cors::Cors;
use actix_web::middleware::from_fn;
use actix_web::{main, middleware::Logger, web, App, HttpServer};
use env_logger::Env;
use models::AppState;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::SqlitePool;
use std::env;
use std::str::FromStr;

mod auth;
mod handlers;
mod middleware;
mod models;

#[main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let options = SqliteConnectOptions::from_str(&database_url)
        .expect("Failed to create SQLite options")
        .create_if_missing(true)
        .to_owned();

    // Connect to the SQLite database with the configured options
    let pool = SqlitePool::connect_with(options)
        .await
        .expect("Failed to connect to the database");

    // Create the users table with refresh_token and refresh_token_expiry fields
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL,
            user_salt TEXT NOT NULL,
            refresh_token TEXT UNIQUE,
            refresh_token_expiry INTEGER
        );
        "#,
    )
    .execute(&pool)
    .await
    .expect("Failed to create tables");

    let (encoding_key, decoding_key) = auth::load_key_pair();
    let state = AppState {
        encoding_key,
        decoding_key,
    };

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(from_fn(middleware::jwt_middleware))
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(state.clone()))
            .service(
                web::scope("/auth")
                    .service(handlers::register_user)
                    .service(handlers::login_user)
                    .service(handlers::refresh_token_handler),
            )
    })
    .bind("0.0.0.0:8081")?
    .run()
    .await
}
