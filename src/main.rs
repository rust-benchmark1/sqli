use actix_web::{web, App, HttpServer};
use sqlx::sqlite::SqlitePoolOptions;
use std::env;
use dotenv::dotenv;

mod handlers;
mod models;


// It sets up the database connection pool, runs migrations, 
// and configures the actix-web server with the vulnerable and secure routes.


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    // Get the database URL from the environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create a connection pool to the database
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create database pool.");

    // Run database migrations
    sqlx::migrate!()
        .run(&pool)
        .await
        .expect("Failed to run database migrations.");

    println!("🚀 Server started successfully at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::scope("/vulnerable")
                    .route("/login", web::post().to(handlers::vulnerable_login)),
            )
            .service(
                web::scope("/secure")
                    .route("/login", web::post().to(handlers::secure_login)),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}


