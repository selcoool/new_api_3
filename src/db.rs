// CREATE TABLE users (
//     id INT AUTO_INCREMENT PRIMARY KEY,
//     email VARCHAR(255) NOT NULL UNIQUE,
//     password TEXT NOT NULL,
//     role VARCHAR(50) NOT NULL DEFAULT 'user'
// );


use sqlx::{MySqlPool, mysql::MySqlPoolOptions};
use std::env;

pub async fn connect_db() -> MySqlPool {
    let url = env::var("DATABASE_URL").expect("Missing DATABASE_URL");

    MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .unwrap()
}