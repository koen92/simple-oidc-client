use crate::config;
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType,
    CoreGenderClaim, CoreIdTokenClaims, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
    CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreRevocableToken, CoreTokenType,
};
use openidconnect::{
    reqwest as oidc_reqwest, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    DiscoveryError, EmptyAdditionalClaims, EmptyExtraTokenFields, IdTokenFields, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RevocationErrorResponseType, Scope, StandardErrorResponse,
    StandardTokenIntrospectionResponse, StandardTokenResponse, TokenResponse,
};
use reqwest;
use serde::{Deserialize, Serialize};
use std::error::Error;

type MyClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
    CoreJsonWebKeyUse,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    StandardTokenResponse<
        IdTokenFields<
            EmptyAdditionalClaims,
            EmptyExtraTokenFields,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
        >,
        CoreTokenType,
    >,
    CoreTokenType,
    StandardTokenIntrospectionResponse<EmptyExtraTokenFields, CoreTokenType>,
    CoreRevocableToken,
    StandardErrorResponse<RevocationErrorResponseType>,
>;

#[derive(Clone)]
pub struct OidcClient {
    client: MyClient,
}

#[derive(Deserialize, Serialize)]
pub struct OidcSession {
    pub nonce: Nonce,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
}

impl OidcClient {
    pub async fn new(
    ) -> Result<OidcClient, DiscoveryError<openidconnect::reqwest::Error<reqwest::Error>>> {
        println!("Discovering issuer...");
        let provider_metadata = CoreProviderMetadata::discover_async(
            config::get().issuer_url.clone(),
            oidc_reqwest::async_http_client,
        )
        .await?;

        let client = MyClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config::get().client_id.to_string()),
            Some(ClientSecret::new(config::get().client_secret.to_string())),
        );
        println!("Found issuer!");
        Ok(OidcClient { client })
    }

    pub fn get_authorization_url(&self) -> (reqwest::Url, OidcSession) {
        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let auth_request = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        // Add the required scopes (need to use fold, because add_scope requires ownership of the data
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
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(auth_code.to_string()))
            .set_pkce_verifier(oidc_session.pkce_verifier)
            .request_async(oidc_reqwest::async_http_client)
            .await?;

        let id_token = token_response
            .id_token()
            .ok_or("no jwt found in oidc response")?;
        let claims = id_token.claims(&self.client.id_token_verifier(), &oidc_session.nonce)?;

        Ok((id_token.to_string(), claims.clone()))
    }
}
