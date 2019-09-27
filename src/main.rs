use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{middleware, web, App, HttpServer};
use argon2rs::{
    defaults::{KIB, LANES, PASSES},
    verifier::Encoded,
    Argon2, Variant,
};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use lazy_static::lazy_static;
use log::error;
use ring::rand::{SecureRandom, SystemRandom};

static DATABASE_URL: &'static str = "DATABASE_URL";
static DOMAIN: &'static str = "DOMAIN";
static LOCAL_SALT: &'static str = "LOCAL_SALT";
static SECRET_KEY: &'static str = "SECRET_KEY";

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

struct SaltedHash {
    salt: [u8; 32],
    salted_hash: String,
}

fn hash_password(password: &str) -> Result<SaltedHash, ()> {
    let sys_rand = SystemRandom::new();

    let local_salt = match std::env::var(LOCAL_SALT) {
        Ok(s) => s,
        Err(e) => {
            error!("{}: {}", LOCAL_SALT, e);
            std::process::exit(1);
        }
    };

    let mut random_salt = [0u8; 32];
    sys_rand.fill(&mut random_salt).unwrap();

    let a2 = Argon2::new(PASSES, LANES, KIB, Variant::Argon2d).expect("initializing Argon2");
    let random_salt_hash = Encoded::new(a2, &random_salt, local_salt.as_bytes(), b"", b"").to_u8();
    let random_salt_hash_encoded = String::from_utf8(random_salt_hash).unwrap();

    let a2 = Argon2::new(PASSES, LANES, KIB, Variant::Argon2d).expect("initializing Argon2");
    let data_hash = Encoded::new(
        a2,
        password.as_bytes(),
        random_salt_hash_encoded.as_bytes(),
        b"",
        b"",
    )
    .to_u8();
    let data_hash_encoded = String::from_utf8(data_hash).unwrap();

    Ok(SaltedHash {
        salt: random_salt,
        salted_hash: data_hash_encoded,
    })
}

fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::set_var(
        "RUST_LOG",
        "pandas_auth=info, actix_web=info,actix_server=info",
    );
    env_logger::init();

    let db_url = match std::env::var(DATABASE_URL) {
        Ok(v) => v,
        Err(e) => {
            error!("{}: {}", DATABASE_URL, e);
            std::process::exit(1);
        }
    };

    let secret_key = std::env::var(SECRET_KEY).expect("SECRET_KEY not defined");

    let manager = ConnectionManager::<PgConnection>::new(db_url);
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Pool creation failed.");
    let domain = std::env::var(DOMAIN).unwrap_or("localhost".to_string());

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .wrap(middleware::Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(secret_key.as_bytes())
                    .name("auth")
                    .path("/")
                    .domain(domain.as_str())
                    .max_age_time(chrono::Duration::days(1))
                    .secure(false),
            ))
            .data(web::JsonConfig::default().limit(4096))
            .service(
                web::scope("/api")
                    .service(web::resource("/invitation").route(web::post().to(|| {})))
                    .service(web::resource("/register/{invite_id}").route(web::post().to(|| {})))
                    .service(
                        web::resource("/auth")
                            .route(web::post().to(|| {}))
                            .route(web::delete().to(|| {}))
                            .route(web::get().to(|| {})),
                    ),
            )
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run()
    .unwrap();

    Ok(())
}
