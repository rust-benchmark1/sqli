-- Create the credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

-- Insert a sample user for demonstration
INSERT INTO credentials (email, password) VALUES ('user1@startup.io', 'password123');