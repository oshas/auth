use ring::{digest, pbkdf2};
use serde_derive::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::{collections::HashMap, num::NonZeroU32};

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

enum Error {
    WrongUsernameOrPassword,
}

struct UserDatabase {
    pbkdf2_iterations: NonZeroU32,
    db_salt_component: [u8; 16],
    storage: HashMap<String, Credential>,
}

impl UserDatabase {
    pub fn store_password(&mut self, username: &str, password: &str) {
        let salt = self.salt(username);
        let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(
            DIGEST_ALG,
            self.pbkdf2_iterations,
            &salt,
            password.as_bytes(),
            &mut to_store,
        );
        self.storage.insert(String::from(username), to_store);
    }

    pub fn verify_password(&self, username: &str, attempted_password: &str) -> Result<(), Error> {
        match self.storage.get(username) {
            Some(actual_password) => {
                let salt = self.salt(username);
                pbkdf2::verify(
                    DIGEST_ALG,
                    self.pbkdf2_iterations,
                    &salt,
                    attempted_password.as_bytes(),
                    actual_password,
                )
                .map_err(|_| Error::WrongUsernameOrPassword)
            }

            None => Err(Error::WrongUsernameOrPassword),
        }
    }

    fn salt(&self, username: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.db_salt_component.len() + username.as_bytes().len());
        salt.extend(&self.db_salt_component);
        salt.extend(username.as_bytes());
        salt
    }
}

#[derive(Deserialize)]
struct Config {
    pbkdf2_iterations: NonZeroU32,
    db_salt_component: [u8; 16],
}

fn read_config_from_file() -> serde_json::Result<Config> {
    let file = File::open("config.json").unwrap();
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

fn main() {
    let cfg = read_config_from_file().unwrap();
    let mut db = UserDatabase {
        pbkdf2_iterations: cfg.pbkdf2_iterations,
        db_salt_component: cfg.db_salt_component,
        storage: HashMap::new(),
    };

    db.store_password("alice", "@74d7]404j|W}6u");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let cfg = read_config_from_file().unwrap();
        let mut db = UserDatabase {
            pbkdf2_iterations: cfg.pbkdf2_iterations,
            db_salt_component: cfg.db_salt_component,
            storage: HashMap::new(),
        };

        db.store_password("alice", "@74d7]404j|W}6u");
        assert!(db.verify_password("alice", "wrong password").is_err());
        assert!(db.verify_password("alice", "@74d7]404j|W}6u").is_ok());
    }
}
