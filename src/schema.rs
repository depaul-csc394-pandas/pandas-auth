table! {
    users (id) {
        id -> Int4,
        username -> Varchar,
        salt_base64 -> Varchar,
        argon2_hash -> Varchar,
    }
}
