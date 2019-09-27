#[macro_use]
extern crate diesel;

mod hash;
mod models;
mod schema;

use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{middleware, web, App, HttpServer};
use diesel::connection::Connection;
use diesel::pg::{Pg, PgConnection};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use hash::SaltedHash;
use lazy_static::lazy_static;
use log::error;
use ring::rand::SystemRandom;

static DATABASE_URL: &'static str = "DATABASE_URL";
static DOMAIN: &'static str = "DOMAIN";
static PEPPER: &'static str = "PEPPER";
static COOKIE_KEY: &'static str = "COOKIE_KEY";

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
type PooledConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

pub fn create_user<C, S>(conn: &PooledConnection, username: S, password: S) -> models::User
where
    S: AsRef<str>,
{
    let SaltedHash { salt, hash } = SaltedHash::from_password(password.as_ref());

    let new_user = models::NewUser {
        username: username.as_ref().to_string(),
        salt_base64: base64::encode(&salt),
        argon2_hash: String::from_utf8(hash).expect("hash into utf8"),
    };

    diesel::insert_into(schema::users::table)
        .values(&new_user)
        .get_result(conn)
        .expect("Error inserting new user")
}

pub fn verify_user<S>(conn: &PooledConnection, username: S, password: S) -> bool
where
    S: AsRef<str>,
{
    let user: models::User = schema::users::table
        .filter(schema::users::username.eq(username.as_ref()))
        .get_result(conn)
        .expect("user query");
    unimplemented!();
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

    let manager = ConnectionManager::<PgConnection>::new(db_url);
    let pool: Pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Pool creation failed.");
    let domain = std::env::var(DOMAIN).unwrap_or("localhost".to_string());

    let cookie_key = std::env::var(COOKIE_KEY).expect("Failed to load COOKIE_KEY");

    HttpServer::new(move || {
        App::new()
            .data(pool.clone())
            .wrap(middleware::Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(cookie_key.as_bytes())
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
