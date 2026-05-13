use actix_web::{
    get,
    post,
    web,
    App,
    HttpRequest,
    HttpResponse,
    HttpServer,
};

use serde::{
    Deserialize,
    Serialize,
};

use sqlx::{
    mysql::MySqlPoolOptions,
    MySqlPool,
};

use bcrypt::{
    hash,
    verify,
    DEFAULT_COST,
};

use jsonwebtoken::{
    decode,
    encode,
    DecodingKey,
    EncodingKey,
    Header,
    Validation,
};

use chrono::{
    Duration,
    Utc,
};

use std::env;

/* ================= REQUEST ================= */

#[derive(Deserialize)]
struct Register {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}

/* ================= JWT ================= */

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    user_id: i32,
    role: String,
    exp: usize,
}

fn jwt_secret() -> String {

    env::var("JWT_SECRET")
        .unwrap()
}

fn create_token(
    user_id: i32,
    role: String,
) -> String {

    let exp = Utc::now()
        .checked_add_signed(
            Duration::hours(24)
        )
        .unwrap()
        .timestamp() as usize;

    let claims = Claims {
        user_id,
        role,
        exp,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(
            jwt_secret().as_bytes()
        ),
    )
    .unwrap()
}

fn verify_token(
    token: &str,
) -> Option<Claims> {

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(
            jwt_secret().as_bytes()
        ),
        &Validation::default(),
    )
    .ok()
    .map(|data| data.claims)
}

/* ================= REGISTER ================= */

#[post("/register")]
async fn register(
    pool: web::Data<MySqlPool>,
    body: web::Json<Register>,
) -> HttpResponse {

    let hashed = hash(
        &body.password,
        DEFAULT_COST,
    )
    .unwrap();

    let result = sqlx::query(
        "
        INSERT INTO users
        (email, password, role)

        VALUES (?, ?, 'user')
        "
    )
    .bind(&body.email)
    .bind(hashed)
    .execute(pool.get_ref())
    .await;

    match result {

        Ok(_) => {

            HttpResponse::Ok()
                .body("Register success")
        }

        Err(error) => {

            HttpResponse::BadRequest()
                .body(error.to_string())
        }
    }
}

/* ================= LOGIN ================= */

#[post("/login")]
async fn login(
    pool: web::Data<MySqlPool>,
    body: web::Json<Login>,
) -> HttpResponse {

    let user = sqlx::query!(
        "
        SELECT
            id,
            password,
            role

        FROM users

        WHERE email = ?
        ",
        body.email
    )
    .fetch_one(pool.get_ref())
    .await;

    if user.is_err() {

        return HttpResponse::Unauthorized()
            .body("User not found");
    }

    let user = user.unwrap();

    // FIX HERE
    let password_hash = user.password;

    let ok = verify(
        &body.password,
        &password_hash,
    )
    .unwrap_or(false);

    if !ok {

        return HttpResponse::Unauthorized()
            .body("Wrong password");
    }

    // FIX HERE
    let role = user.role;

    let token = create_token(
        user.id,
        role,
    );

    HttpResponse::Ok().json(
        serde_json::json!({
            "token": token
        })
    )
}

/* ================= PROFILE ================= */

#[get("/profile")]
async fn profile(
    req: HttpRequest,
) -> HttpResponse {

    let auth = req
        .headers()
        .get("Authorization");

    if auth.is_none() {

        return HttpResponse::Unauthorized()
            .body("No token");
    }

    let token = auth
        .unwrap()
        .to_str()
        .unwrap();

    let token = token
        .strip_prefix("Bearer ")
        .unwrap_or("");

    match verify_token(token) {

        Some(data) => {

            HttpResponse::Ok().json(
                serde_json::json!({
                    "user_id": data.user_id,
                    "role": data.role
                })
            )
        }

        None => {

            HttpResponse::Unauthorized()
                .body("Invalid token")
        }
    }
}

/* ================= MAIN ================= */

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    dotenvy::dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .unwrap();

    let pool = MySqlPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap();

    println!("SERVER RUNNING => 8080");

    HttpServer::new(move || {

        App::new()

            .app_data(
                web::Data::new(pool.clone())
            )

            .service(register)

            .service(login)

            .service(profile)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}