use actix::prelude::*;
use actix_web::{
    fs::{self, NamedFile},
    http, server, App, AsyncResponder, HttpMessage, HttpRequest, HttpResponse,
};
use futures::Future;
use serde_derive::Deserialize;

mod db;

struct ServerState {
    db: Addr<db::DbExecutor>,
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
        .and_then(move |val: db::VerifyLogin| {
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
        let addr = SyncArbiter::start(3, move || {
            db::DbExecutor({
                let mut db = db::UserDatabase::from_config_file();
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
