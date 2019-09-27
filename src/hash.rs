use argon2rs::{verifier::Encoded, Argon2, Variant};
use ring::rand::{SecureRandom, SystemRandom};
use std::io::Write;

/// Generate a random 32-byte salt value.
fn random_salt(rng: &SystemRandom) -> [u8; 32] {
    let mut salt = [0; 32];
    rng.fill(&mut salt).unwrap();
    salt
}

/// Retrieve the local pepper value from `.env`.
fn pepper() -> [u8; 32] {
    let pepper_str = std::env::var(crate::PEPPER).expect("Failed to load PEPPER");
    let mut pepper = [0; 32];
    pepper_str
        .into_bytes()
        .write_all(&mut pepper)
        .expect("Failed to write bytes");
    pepper
}

fn argon2_session(salt: [u8; 32], password: &str) -> Encoded {
    let pepper = pepper();
    Encoded::new(
        Argon2::default(Variant::Argon2d),
        password.as_bytes(),
        &salt,
        &pepper,
        b"",
    )
}

pub struct SaltedHash {
    salt: [u8; 32],
    hash: Vec<u8>,
}

impl SaltedHash {
    /// Generate a random salt, then salt and pepper the password
    pub fn from_password(rng: &SystemRandom, password: &str) -> SaltedHash {
        let salt = random_salt(rng);
        let session = argon2_session(salt, password);
        let hash = session.to_u8();
        println!("Hash len: {}", hash.len());

        SaltedHash { salt, hash }
    }

    pub fn verify(&self, password: &str) -> bool {
        self.hash == argon2_session(self.salt, password).to_u8()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    static TEST_PEPPER: &'static str = "NAqdplo5YPcZ84UbCCvWH9OOTJOXAEzr";

    #[test]
    fn test_verify() {
        std::env::set_var(crate::PEPPER, TEST_PEPPER);
        let rng = SystemRandom::new();
        let password = "some_other_password";
        let sh = SaltedHash::from_password(&rng, password);
        assert_eq!(sh.verify(password), true);
    }
}
