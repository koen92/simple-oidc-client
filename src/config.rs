use config::Config;
use once_cell::sync::OnceCell;
use openidconnect::IssuerUrl;
use rand::Rng;
use serde::Deserialize;

static SETTINGS: OnceCell<MyConfig> = OnceCell::new();
const PREFIX: &str = "APP";

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct MyConfig {
    pub port: u16,
    pub issuer_url: IssuerUrl,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub session_secret: String,
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
            client_secret: String::from(""),
            scopes: vec![String::from("openid")],
            session_secret,
        }
    }
}

impl MyConfig {
    fn validate(&self) {
        assert_ne!(
            self.client_id.to_string(),
            "",
            "APP_CLIENT_ID env var cannot be empty"
        );
        assert_ne!(
            self.client_secret.to_string(),
            "",
            "APP_CLIENT_SECRET env var cannot be empty"
        );
        assert_ne!(
            self.issuer_url.to_string(),
            "https://accounts.example.com",
            "APP_ISSUER_URL env var cannot be empty"
        );
        assert!(
            self.session_secret.len() > 64,
            "APP_SESSION_SECRET must be at least 64 bytes"
        );
    }
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
