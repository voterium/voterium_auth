use actix_web::{web, App, HttpServer};
use actix_web::main;
use actix_cors::Cors;
use sqlx::SqlitePool;
use std::env;

mod auth;
mod handlers;
mod models;
#[main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    // Create tables if they don't exist
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        "#
    )
    .execute(&pool)
    .await
    .expect("Failed to create tables");

    HttpServer::new(move || {
        let cors = Cors::permissive();
        
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(handlers::register_user)
            .service(handlers::login_user)
            .service(handlers::refresh_token_handler)
    })
    .bind("0.0.0.0:8081")?
    .run()
    .await
}
