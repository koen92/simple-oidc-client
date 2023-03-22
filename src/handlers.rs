use crate::oidc::{OidcClient, OidcSession};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json, Redirect},
};
use axum_sessions::extractors::{ReadableSession, WritableSession};
use serde::Deserialize;
use serde_json::{json, Value};

type JsonResponse = (StatusCode, Json<Value>);

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

pub async fn handle_authorize(
    mut session: WritableSession,
    State(oidc_client): State<OidcClient>,
) -> Result<Redirect, JsonResponse> {
    let (url, oidc_session) = oidc_client.get_authorization_url();

    session
        .insert("oidc_session", oidc_session)
        .or_else(|err| {
            println!("Error storing session: {:?}", err);
            Err(session_error())
        })?;

    Ok(Redirect::to(url.as_str()))
}

pub async fn handle_callback(
    session: ReadableSession,
    State(oidc_client): State<OidcClient>,
    Query(params): Query<CallbackParams>,
) -> Result<JsonResponse, JsonResponse> {
    let oidc_session = session
        .get::<OidcSession>("oidc_session")
        .ok_or_else(session_error)?;

    if *oidc_session.csrf_token.secret() != params.state {
        return Err(session_error());
    }

    match oidc_client
        .grant_auth_code(&params.code, oidc_session)
        .await
    {
        Ok(result) => Ok((
            StatusCode::OK,
            Json(json!({ "id_token": result.0, "claims": result.1 })),
        )),
        Err(err) => {
            println!("error in grant: {}", err);
            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "cannot grant auth code" })),
            ))
        }
    }
}

fn session_error() -> JsonResponse {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid session" })),
    )
}
