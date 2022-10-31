extern crate core;

use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use axum::error_handling::HandleErrorLayer;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::WebSocketUpgrade;
use axum::headers::authorization::Bearer;
use axum::headers::Authorization;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{http, middleware, BoxError, Extension, Json, Router, TypedHeader};
use futures::{sink::SinkExt, stream::StreamExt};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, Mutex};
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;

static SECRET: &str = "Hello, world!";

// Our shared state
struct AppState {
    user_set: Mutex<HashSet<String>>,
    tx: broadcast::Sender<String>,
}

#[tokio::main]
async fn main() {
    let app_state = Arc::new(AppState {
        user_set: Mutex::new(HashSet::new()),
        tx: broadcast::channel(2048).0,
    });

    let app = Router::new()
        .route("/login", post(login))
        .route("/get_data_without_auth", get(get_data_without_auth))
        .route("/get_data_with_auth", get(get_data_with_auth))
        .layer(middleware::from_fn(auth_token))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_error))
                .layer(TimeoutLayer::new(Duration::from_secs(10))),
        )
        .route("/ping", get(ping))
        .route("/ws", get(handle_websocket))
        .layer(Extension(app_state));

    axum::Server::bind(&"0.0.0.0:8888".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handle_websocket(
    ws: WebSocketUpgrade,
    Extension(app_state): Extension<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(|stream| async move {
        let (tx, mut rx) = stream.split();

        // we need to send ping message to client every 10 seconds
        let arc_tx = Arc::new(Mutex::new(tx));
        let tx1 = arc_tx.clone();
        tokio::spawn(async move {
            loop {
                thread::sleep(Duration::from_secs(10));
                let message = Message::Ping("ping".into());
                let mut sender = tx1.lock().await;
                match sender.send(message).await {
                    Ok(_) => {
                        println!("sent ping");
                    }
                    Err(e) => {
                        println!("send error: {}", e);
                        break;
                    }
                };
            }
        });

        let tx2 = arc_tx.clone();
        while let Some(Ok(message)) = rx.next().await {
            let mut sender = tx2.lock().await;
            // handle messages from the client
            match message {
                Message::Text(text) => {
                    let mut user_set = app_state.user_set.lock().await;
                    user_set.insert(text.clone());
                    let message = Message::Text(text.into());
                    sender.send(message).await.unwrap();
                }
                Message::Pong(_) => {
                    println!("received pong");
                }
                Message::Close(_) => {
                    println!("Websocket connection closed");
                    break;
                }
                _ => {}
            }
        }
    })
}

async fn ping() -> &'static str {
    "pong"
}

async fn login(Json(payload): Json<Auth>) -> impl IntoResponse {
    println!("{} {}", payload.username, payload.password);
    authorize().await
}

async fn get_data_without_auth(Extension(user_info): Extension<UserInfo>) -> impl IntoResponse {
    println!("get_data_without_auth: {:?}", user_info);
    "getDataWithoutAuth".into_response()
}

async fn get_data_with_auth(
    payload: Option<TypedHeader<Authorization<Bearer>>>,
) -> impl IntoResponse {
    if let Some(header) = payload {
        let token = header.token();

        // `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
        let claims = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(SECRET.as_ref()),
            &Validation::default(),
        )
        .unwrap()
        .claims;

        let user_info = UserInfo {
            username: claims.username,
        };
        println!("success {:?}", user_info);
        return (StatusCode::OK, "getDataWithAuth".into());
    }
    (StatusCode::BAD_REQUEST, format!("Unauthorized"))
}

async fn auth_token<B>(mut req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    if let Some(token) = auth_header {
        let access_token = token.replace("Bearer ", "");

        // `token` is a struct with 2 fields: `header` and `claims` where `claims` is your own struct.
        let claims = decode::<Claims>(
            &access_token,
            &DecodingKey::from_secret(SECRET.as_ref()),
            &Validation::default(),
        )
        .unwrap()
        .claims;

        let user_info = UserInfo {
            username: claims.username,
        };
        req.extensions_mut().insert(user_info);
        return Ok(next.run(req).await);
    }
    return Ok("unauthorize".into_response());
}

async fn authorize() -> impl IntoResponse {
    let claims = Claims {
        username: "feifei".into(),
        exp: 2000000000,
    };
    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_ref()),
    )
    .unwrap();
    access_token.into_response()
}

#[derive(Debug, Deserialize)]
struct Auth {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    username: String,
    exp: usize,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
struct UserInfo {
    username: String,
}

async fn handle_error(err: BoxError) -> (StatusCode, String) {
    println!("hello");
    (StatusCode::BAD_REQUEST, format!("Unauthorized: {}", err))
}
