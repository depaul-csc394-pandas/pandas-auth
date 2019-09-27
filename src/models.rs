use crate::schema::users;
use diesel::prelude::*;

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
