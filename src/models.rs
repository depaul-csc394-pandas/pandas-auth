use crate::{hash::SaltedHash, schema::users};
use std::io::Write;

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser {
    pub username: String,
    pub salt_base64: String,
    pub argon2_hash: String,
}

#[derive(Queryable)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub salt_base64: String,
    pub argon2_hash: String,
}

impl User {
    pub fn verify<S>(&self, password: S) -> bool
    where
        S: AsRef<str>,
    {
        let mut salt = [0u8; 32];
        (&mut salt[..]).write_all(&base64::decode(&self.salt_base64).expect("base64 decode"))
            .expect("write_all");

        SaltedHash {
            salt,
            hash: self.argon2_hash.clone().into_bytes(),
        }
        .verify(password.as_ref())
    }
}
