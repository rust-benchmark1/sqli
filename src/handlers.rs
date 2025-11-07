use actix_web::{web, HttpResponse, Responder};
use sqlx::{query, query_as, SqlitePool};
use crate::models::{LoginRequest, User};

/// ## Vulnerable Login Handler
///
/// **Vulnerability**: SQL Injection 
/// This handler is vulnerable because it constructs a SQL query by directly concatenating
/// user-provided input (`email` and `password`) into the query string. [cite: 75]
/// An attacker can provide specially crafted input to change the query's logic. [cite: 15]
/// For example, using a password like `' OR 1=1; --` can bypass authentication. [cite: 53, 54]
pub async fn vulnerable_login(
    req: web::Json<LoginRequest>,
    db_pool: web::Data<SqlitePool>,
) -> impl Responder {
    let email = &req.email;
    // Use an empty string if password is not provided
    let password = req.password.as_deref().unwrap_or("");

    // DANGER: Building a query with format! is unsafe and leads to SQLi.
    let query_string = format!(
        "SELECT * FROM credentials WHERE email = '{}' AND password = '{}'",
        email, password
    );

    println!("Executing vulnerable query: {}", query_string);

    // query! macro is generally safe, but not when the string is formatted beforehand.
    // We use sqlx::query here to execute the raw, interpolated string.
    let result = query(&query_string).fetch_optional(db_pool.get_ref()).await;

    match result {
        Ok(Some(_user)) => HttpResponse::Ok().body("Vulnerable Login Successful!"),
        Ok(None) => HttpResponse::Unauthorized().body("Vulnerable Login Failed: Invalid credentials."),
        Err(e) => {
            // The database error reveals syntax issues, confirming the injection point. 
            HttpResponse::InternalServerError().body(format!("Database error: {}", e))
        }
    }
}

/// ## Secure Login Handler
///
/// **Mitigation**: Parameterized Queries [cite: 110]
/// This handler mitigates SQL injection by using parameterized queries (also known as
/// prepared statements). The `?` placeholder is used for input values. [cite: 118]
/// The database driver receives the query and the parameters separately, treating the
/// user input strictly as data, not as executable SQL code. [cite: 111, 113, 120]
/// This prevents malicious input from altering the query's logic.
pub async fn secure_login(
    req: web::Json<LoginRequest>,
    db_pool: web::Data<SqlitePool>,
) -> impl Responder {
    let email = &req.email;
    // Use an empty string if password is not provided
    let password = req.password.as_deref().unwrap_or("");

    // SAFE: Using query_as with `?` placeholders for parameters.
    // sqlx will safely bind the `email` and `password` variables.
    let result = query_as::<_, User>("SELECT * FROM credentials WHERE email = ? AND password = ?")
        .bind(email)
        .bind(password)
        .fetch_optional(db_pool.get_ref())
        .await;

    match result {
        Ok(Some(_user)) => HttpResponse::Ok().body("Secure Login Successful!"),
        Ok(None) => HttpResponse::Unauthorized().body("Secure Login Failed: Invalid credentials."),
        Err(e) => HttpResponse::InternalServerError().body(format!("An unexpected error occurred: {}", e)),
    }
}