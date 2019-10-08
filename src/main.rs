#[macro_use]
extern crate diesel;

mod error;
mod hash;
mod models;
mod resource;
mod schema;
mod secret;

use actix_identity::{CookieIdentityPolicy, IdentityService};
use actix_web::{middleware, web, App, HttpServer};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use hash::SaltedHash;
use lazy_static::lazy_static;
use log::{error, info};
use ring::rand::SystemRandom;

static DATABASE_URL: &'static str = "DATABASE_URL";
static DOMAIN: &'static str = "DOMAIN";

lazy_static! {
    static ref RNG: SystemRandom = SystemRandom::new();
}

type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
type PooledConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

// TODO: needs testing!
pub fn create_user<S>(conn: &PooledConnection, username: S, password: S) -> models::User
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

/// API Guide (keep updated!)
/// - /api/register
///     - POST { username, password }: register user
/// - /api/auth
///     - POST { username, password }: log user in
///     - DELETE { token }: log user out
///     - GET { token }: get user data

fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    std::env::set_var("RUST_LOG", "pandas_auth=info,actix_web=info,diesel=info");
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

    HttpServer::new(move || {
        info!("Starting HTTP server...");
        App::new()
            .data(pool.clone())
            .wrap(middleware::Logger::default())
            .wrap(IdentityService::new(
                CookieIdentityPolicy::new(&*secret::COOKIE_KEY)
                    .name("auth-cookie")
                    .path("/")
                    .domain(domain.as_str())
                    .max_age_time(chrono::Duration::days(1))
                    .secure(false),
            ))
            .data(web::JsonConfig::default().limit(4096))
            .service(
                web::scope("/api")
                    .service(
                        web::resource("/register").route(web::post().to_async(resource::register)),
                    )
                    .service(
                        web::resource("/auth")
                            .route(web::post().to_async(resource::login))
                            .route(web::delete().to(resource::logout))
                            .route(web::get().to(|| {})),
                    ),
            )
    })
    .bind("localhost:8080")
    .unwrap()
    .run()
    .unwrap();

    Ok(())
}
