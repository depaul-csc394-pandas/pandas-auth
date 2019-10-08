use lazy_static::lazy_static;
use log::error;
use std::{
    fs::File,
    io::{ErrorKind, Read},
    path::Path,
};

// these secret values are loaded from /run/secrets at runtime
#[cfg(not(test))]
lazy_static! {
    pub static ref PEPPER: [u8; 32] = {
        let mut reader = secret("pandas_auth_pepper");
        let mut data = [0; 32];
        match reader.read(&mut data) {
            Ok(_) => data,
            Err(e) => {
                error!("Failed to read pandas_auth_pepper: {}", e);
                std::process::exit(1);
            }
        }
    };
    pub static ref COOKIE_KEY: [u8; 32] = {
        let mut reader = secret("pandas_auth_cookie_key");
        let mut data = [0; 32];
        match reader.read(&mut data) {
            Ok(_) => data,
            Err(e) => {
                error!("Failed to read pandas_auth_cookie_key: {}", e);
                std::process::exit(1);
            }
        }
    };
}

// we don't have access to Docker secrets in the test environment, so we hardcode
// a different set of secrets to be used in test builds.
#[cfg(test)]
lazy_static! {
    pub static ref PEPPER: [u8; 32] = {
        let pepper_str = "NAqdplo5YPcZ84UbCCvWH9OOTJOXAEzr".to_string();
        let mut bytes = [0; 32];
        pepper_str.as_bytes().read(&mut bytes).unwrap();
        bytes
    };
    pub static ref COOKIE_KEY: [u8; 32] = {
        let cookie_key_str = "ChzeqPjoSsrdO5xZ14gMoaW67yMn5Ev1".to_string();
        let mut bytes = [0; 32];
        cookie_key_str.as_bytes().read(&mut bytes).unwrap();
        bytes
    };
}

fn secret<S>(name: S) -> impl Read
where
    S: AsRef<str>,
{
    let path = Path::new("/run/secrets").join(name.as_ref());
    let path_str = path.to_str().unwrap();

    let f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                ErrorKind::NotFound => error!(
                    "{} not found. Make sure to create the '{}' secret with \
                     'docker secret create' before starting the service.",
                    path_str,
                    name.as_ref(),
                ),
                _ => error!("Failed to open {}: {}", path_str, e),
            }

            std::process::exit(1);
        }
    };

    f
}
