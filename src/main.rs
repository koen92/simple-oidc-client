use axum::{response::Redirect, routing::get, Router};
use axum_sessions::{async_session::MemoryStore, SameSite, SessionLayer};

mod config;
mod handlers;
mod oidc;

#[tokio::main]
async fn main() {
    config::init();

    println!("Config: {:?}", config::get());
    let state = oidc::OidcClient::new()
        .await
        .expect("OIDC Discovery failed");

    let store = MemoryStore::new();
    let session_layer = SessionLayer::new(store, config::get().session_secret.as_bytes())
        .with_same_site_policy(SameSite::Lax);

    // build our application with a router
    let app = Router::new()
        .route("/", get(|| async { Redirect::to("/oidc/login") }))
        .route("/oidc/login", get(handlers::handle_authorize))
        .route("/oidc/callback", get(handlers::handle_callback))
        .layer(session_layer)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", config::get().port);
    // run it with hyper
    axum::Server::bind(&addr.parse().expect("cannot parse listening address"))
        .serve(app.into_make_service())
        .await
        .expect("cannot bind to port, already in use?");
}
