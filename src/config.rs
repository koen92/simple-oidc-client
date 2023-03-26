use config::Config;
use josekit::jws::{alg::rsassa::RsassaJwsSigner, RS256};
use once_cell::sync::OnceCell;
use openidconnect::IssuerUrl;
use rand::Rng;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::env;
use std::fmt::{Display, Formatter};
use x509_parser::pem::parse_x509_pem;

static SETTINGS: OnceCell<MyConfig> = OnceCell::new();
const PREFIX: &str = "APP";

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct MyConfig {
    pub port: u16,
    pub issuer_url: IssuerUrl,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub session_secret: String,

    #[serde(skip, default = "parse_private_jwt_cert")]
    pub private_jwt_cert_hash: Option<Vec<u8>>,
    #[serde(skip, default = "parse_private_jwt_key")]
    pub private_jwt_key: Option<RsassaJwsSigner>,
}

impl Default for MyConfig {
    fn default() -> Self {
        let rng = rand::thread_rng();
        let session_secret = rng
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(96)
            .map(char::from)
            .collect();
        Self {
            port: 3000,
            issuer_url: IssuerUrl::new(String::from("https://accounts.example.com"))
                .expect("cannot parse issuer url"),
            client_id: String::from(""),
            client_secret: None,
            scopes: vec![String::from("openid")],
            session_secret,
            private_jwt_cert_hash: None,
            private_jwt_key: None,
        }
    }
}

impl Display for MyConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let auth_type = match self.client_secret {
            Some(_) => "Client Secret",
            None => "Private Key JWT",
        };

        write!(
            f,
            "Listen Port: {}\nClientID:    {}\nIssuer:      {}\nAuth type:   {}",
            self.port,
            self.client_id,
            self.issuer_url.as_str(),
            auth_type,
        )
    }
}

impl MyConfig {
    fn validate(&self) {
        assert_ne!(
            self.client_id.to_string(),
            "",
            "APP_CLIENT_ID env var cannot be empty"
        );

        if self.client_secret.is_some() {
            assert!(
                self.private_jwt_key.is_none(),
                "APP_PRIVATE_JWT_KEY cannot be set if APP_CLIENT_SECRET is set!"
            );
            assert_eq!(
                self.private_jwt_cert_hash, None,
                "APP_PRIVATE_JWT_CERT cannot be set if APP_CLIENT_SECRET is set!"
            );
        } else {
            assert!(
                self.private_jwt_key.is_some() && self.private_jwt_cert_hash.is_some(),
                "Either a client secret or a private cert+key must be supplied!"
            );
        }

        assert_ne!(
            self.issuer_url.to_string(),
            "https://accounts.example.com",
            "APP_ISSUER_URL env var cannot be empty"
        );
        assert!(
            self.session_secret.len() >= 64,
            "APP_SESSION_SECRET must be at least 64 bytes"
        );
    }
}

fn parse_private_jwt_cert() -> Option<Vec<u8>> {
    let raw_cert = env::var(format!("{}_PRIVATE_JWT_CERT", PREFIX)).ok()?;

    let parsed_cert = match parse_x509_pem(raw_cert.as_bytes()) {
        Ok((rem, pem)) => {
            assert!(rem.is_empty(), "extra data after parsing AAD Cert");
            pem.contents
        }
        Err(res) => panic!("cannot parse AAD Cert: {:?}", res),
    };

    let mut hasher = Sha1::new();
    hasher.update(parsed_cert);
    let hash = hasher.finalize();

    Some(hash.to_vec())
}

fn parse_private_jwt_key() -> Option<RsassaJwsSigner> {
    let raw_key = env::var(format!("{}_PRIVATE_JWT_KEY", PREFIX)).ok()?;

    Some(
        RS256
            .signer_from_pem(raw_key)
            .expect(format!("cannot parse {}_PRIVATE_KEY", PREFIX).as_str()),
    )
}

pub fn init() {
    let settings = Config::builder()
        .add_source(config::Environment::with_prefix(PREFIX))
        .add_source(
            config::Environment::with_prefix(PREFIX)
                .try_parsing(true)
                .separator("_")
                .list_separator(" "),
        )
        .build()
        .expect("cannot read config from environment")
        .try_deserialize::<MyConfig>()
        .expect("cannot parse config from environment");

    settings.validate();
    SETTINGS.set(settings).expect("cannot set global config");
}

pub fn get() -> &'static MyConfig {
    SETTINGS.get().expect("config not initialized")
}
