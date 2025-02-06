//! # Security Scheme
//!
//! Poem security scheme.

use chrono::prelude::*;
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::Request;
use poem_openapi::{auth::ApiKey, SecurityScheme};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::cli::Args;

/// # Api Security Scheme
///
/// ### ***Important***
/// This Value Can Be Left With A Blank Space As It's Overwriten By Browser Cookies.
///
/// E.g: `' '`
#[derive(SecurityScheme)]
#[oai(
    ty = "api_key",
    key_name = "ActiveUserToken",
    key_in = "cookie",
    checker = "api_security_token_checker"
)]
pub struct ApiSecurityScheme(pub UserToken);

/// could be modifyed to check if values line up in db but just a idea
async fn api_security_token_checker(request: &Request, api_key: ApiKey) -> Option<UserToken> {
    let server_secret = request.data::<ServerSecret>().unwrap();
    VerifyWithKey::verify_with_key(api_key.key.as_str(), server_secret).unwrap()
}

/// Server Secret Hasing Type
pub type ServerSecret = Hmac<Sha256>;

/// UserToken Info Stored in The Browser Cookie/Token
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserToken {
    /// Client Identifier Refrances in The Database
    pub client_identifier: String,
    /// Client Secret For Authenticating The Client
    pub client_secret: String,
    /// The User Name Matches Database
    pub user_name: String,
    /// The Date & Time of The Encoding of the Cookie
    pub creation_date: DateTime<Local>,
}

/// Sets default values for [`UserToken`] Struct
impl Default for UserToken {
    fn default() -> Self {
        Self {
            client_identifier: Uuid::new_v4().to_string(),
            client_secret: "UnSet".to_string(),
            user_name: "UnSet".to_string(),
            creation_date: Local::now(),
        }
    }
}

/// Adding Of Helper Functions
impl UserToken {
    /// generates the response header that sets the cookie in browser
    pub fn to_cookie_string(
        &self,
        args: &Args,
        hmac: ServerSecret,
        cookie_name: Option<String>,
    ) -> String {
        let secure: String = match args.https {
            true => "; Secure".to_string(),
            false => "".to_string(),
        };

        let user_token: UserToken = self.clone();

        let signed_user_token = user_token
            .sign_with_key(&hmac)
            .expect("Couldn't Sign User Token");

        format!(
            "{}={}; Max-Age=15778800; SameSite=Secure; Path=/api; Domain={}{secure}",
            cookie_name.unwrap_or("ActiveUserToken".to_string()),
            signed_user_token,
            args.domain
        )
    }
}
