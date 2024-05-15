use crate::config;
use anyhow::anyhow;
use josekit::{
    jws::JwsHeader,
    jwt::{self, JwtPayload},
    JoseError,
};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreErrorResponseType,
    CoreIdTokenClaims, CoreProviderMetadata, CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    reqwest as oidc_reqwest, AuthorizationCode, ClientId, ClientSecret, CodeTokenRequest,
    CsrfToken, DiscoveryError, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardErrorResponse, TokenResponse,
};
use reqwest::Error as ReqwestError;
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    time::{Duration, SystemTime},
};

type TokenRequest<'a> = CodeTokenRequest<
    'a,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenType,
>;

#[derive(Clone)]
pub struct OidcClient {
    client: CoreClient,
    auth_method: CoreClientAuthMethod,
    token_endpoint: String,
}

#[derive(Deserialize, Serialize)]
pub struct OidcSession {
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
}

impl OidcClient {
    pub async fn new(
    ) -> Result<OidcClient, DiscoveryError<openidconnect::reqwest::Error<ReqwestError>>> {
        println!("Discovering issuer...");
        let provider_metadata = CoreProviderMetadata::discover_async(
            config::get().issuer_url.clone(),
            oidc_reqwest::async_http_client,
        )
        .await?;

        let token_endpoint = provider_metadata
            .token_endpoint()
            .ok_or(DiscoveryError::Other(String::from(
                "no token endpoint found in discovery data",
            )))?
            .to_string();

        let redirect_uri = RedirectUrl::new(format!(
            "http://localhost:{}/oidc/callback",
            config::get().port
        ))
        .or(Err(DiscoveryError::<
            openidconnect::reqwest::Error<ReqwestError>,
        >::Other(String::from("invalid redirect uri"))))?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config::get().client_id.to_string()),
            config::get()
                .client_secret
                .as_ref()
                .and_then(|client_secret| Some(ClientSecret::new(client_secret.to_string()))),
        )
        .set_redirect_uri(redirect_uri);

        let auth_method;
        if config::get().private_jwt_key.is_some() && config::get().private_jwt_cert_hash.is_some()
        {
            auth_method = CoreClientAuthMethod::PrivateKeyJwt;
        } else {
            auth_method = CoreClientAuthMethod::ClientSecretPost;
        }

        println!("Found issuer!");
        Ok(OidcClient {
            client,
            auth_method,
            token_endpoint,
        })
    }

    pub fn get_authorization_url(&self) -> (reqwest::Url, OidcSession) {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let auth_request = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        // Add the required scopes (need to use fold, because add_scope requires ownership of the data)
        let auth_request = config::get()
            .scopes
            .iter()
            .filter(|el| el.as_str() != "openid") // OpenId is by default already present
            .fold(auth_request, |auth_request, scope| {
                auth_request.add_scope(Scope::new(scope.to_string()))
            });

        let (auth_url, csrf_token, nonce) = auth_request.set_pkce_challenge(pkce_challenge).url();
        (
            auth_url,
            OidcSession {
                pkce_verifier,
                nonce,
                csrf_token,
            },
        )
    }

    pub async fn grant_auth_code(
        &self,
        auth_code: &str,
        oidc_session: OidcSession,
    ) -> Result<(String, CoreIdTokenClaims), Box<dyn Error>> {
        let token_request = self
            .client
            .exchange_code(AuthorizationCode::new(auth_code.to_string()))
            .set_pkce_verifier(oidc_session.pkce_verifier);

        let token_request = match self.auth_method {
            CoreClientAuthMethod::PrivateKeyJwt => {
                add_private_jwt_params(&self.token_endpoint, token_request)?
            }
            _ => token_request,
        };

        let token_response = token_request
            .request_async(oidc_reqwest::async_http_client)
            .await?;

        let id_token = token_response
            .id_token()
            .ok_or("no jwt found in oidc response")?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &oidc_session.nonce)?;

        Ok((id_token.to_string(), claims.clone()))
    }
}

fn add_private_jwt_params<'a>(
    issuer_url: &'a str,
    token_request: TokenRequest<'a>,
) -> Result<TokenRequest<'a>, JoseError> {
    let jwt = sign_auth_jwt(issuer_url)?;

    Ok(token_request
        .add_extra_param(
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        )
        .add_extra_param("client_assertion", jwt))
}

fn create_auth_jwt(token_endpoint: &str) -> Result<(JwsHeader, JwtPayload), JoseError> {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    header.set_x509_certificate_sha1_thumbprint(
        config::get()
            .private_jwt_cert_hash
            .as_ref()
            .ok_or(JoseError::InvalidKeyFormat(anyhow!(
                "No private jwt cert found"
            )))?,
    );

    let mut payload = JwtPayload::new();
    payload.set_audience(vec![token_endpoint]);
    payload.set_issuer(&config::get().client_id);
    payload.set_subject(&config::get().client_id);
    payload.set_jwt_id(uuid::Uuid::new_v4().to_string());

    let current_time = SystemTime::now();
    payload.set_issued_at(&current_time);
    payload.set_not_before(&current_time);
    let expiry_time = current_time + Duration::from_secs(120);
    payload.set_expires_at(&expiry_time);

    Ok((header, payload))
}

fn sign_auth_jwt(token_endpoint: &str) -> Result<String, JoseError> {
    let (header, payload) = create_auth_jwt(token_endpoint)?;

    let signer = config::get()
        .private_jwt_key
        .as_ref()
        .ok_or(JoseError::InvalidKeyFormat(anyhow!(
            "No private jwt key found"
        )))?;
    let jwt = jwt::encode_with_signer(&payload, &header, signer)?;

    Ok(jwt)
}
