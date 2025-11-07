use serde::{Deserialize, Serialize};
use sqlx::FromRow;

// Represents the incoming JSON payload for a login request.
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: Option<String>, // Password can be optional for some requests
}

// Represents a user record fetched from the 'credentials' table.
#[derive(Serialize, FromRow)]
pub struct User {
    pub id: i64,
    pub email: String,
    // Note: We are selecting the password here for demonstration.
    // In a real application, you should NEVER send the password hash to the client.
    pub password: String,
}
