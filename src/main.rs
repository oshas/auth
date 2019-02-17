use actix::prelude::*;
use actix_web::{
    fs::{self, NamedFile},
    http, server, App, AsyncResponder, HttpMessage, HttpRequest, HttpResponse,
};
use futures::{future, Future};
use ring::{digest, pbkdf2};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
pub type Credential = [u8; CREDENTIAL_LEN];

pub enum Error {
    WrongUsernameOrPassword,
}

pub struct UserDatabase {
    pbkdf2_iterations: u32,
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
    pbkdf2_iterations: u32,
    db_salt_component: [u8; 16],
}

impl Config {
    fn from_file() -> serde_json::Result<Config> {
        let file = File::open("config.json").unwrap();
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }
}

struct DbExecutor(UserDatabase);

impl Actor for DbExecutor {
    type Context = SyncContext<Self>;
}

#[derive(Debug, Deserialize)]
struct VerifyLogin {
    user: String,
    password: String,
}

impl Message for VerifyLogin {
    type Result = Result<bool, Error>;
}

impl Handler<VerifyLogin> for DbExecutor {
    type Result = Result<bool, Error>;

    fn handle(&mut self, msg: VerifyLogin, _: &mut Self::Context) -> Self::Result {
        Ok(self.0.verify_password(&msg.user, &msg.password).is_ok())
    }
}

struct ServerState {
    db: Addr<DbExecutor>,
}

fn index(_req: &HttpRequest<ServerState>) -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("static/index.html")?)
}

#[derive(Debug, Deserialize)]
struct LoginAttempt {
    user: String,
    password: String,
}

fn try_login(
    req: HttpRequest<ServerState>,
) -> Box<Future<Item = HttpResponse, Error = actix_web::Error>> {
    req.json()
        .from_err()
        .and_then(move |val: VerifyLogin| {
            println!("JSON: {:?}", val);
            req.state()
                .db
                .send(val)
                .from_err()
                .and_then(|res| match res {
                    Ok(success) => Ok(HttpResponse::Ok().json(success)),
                    Err(_) => Ok(HttpResponse::InternalServerError().into()),
                })
        })
        .responder()
}

fn main() {
    println!("Starting server!");
    server::new(move || {
        let cfg = Config::from_file().unwrap();

        let addr = SyncArbiter::start(3, move || {
            DbExecutor({
                let mut db = UserDatabase {
                    pbkdf2_iterations: cfg.pbkdf2_iterations,
                    db_salt_component: cfg.db_salt_component,
                    storage: HashMap::new(),
                };
                db.store_password("alice", "finkatt");
                db
            })
        });
        let state = ServerState { db: addr.clone() };

        let static_files =
            fs::StaticFiles::new("static/").expect("Failed to create static files handler");

        App::with_state(state)
            .resource("/", |r| r.f(index))
            .route("/login", http::Method::POST, try_login)
            .handler("/static", static_files)
    })
    .bind("localhost:8088")
    .unwrap()
    .run();

    /*use std::io::{self, BufRead};
    let stdin = io::stdin();
    let mut it = stdin.lock().lines();
    loop {
        println!("Enter a username:");
        let user = it.next().unwrap().expect("expected string");
        println!("Enter a username:");
        let password = it.next().unwrap().expect("expected string");
        println!("User is {}.", user);
        match db.verify_password(&user, &password).is_ok() {
            true => println!("Login success!"),
            false => println!("Login bad!"),
        }
    }*/
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_storage() {
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
