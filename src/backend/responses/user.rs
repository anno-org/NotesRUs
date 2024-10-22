use chrono::{DateTime, FixedOffset};
use poem_openapi::{payload::Json, ApiResponse, Object};

#[derive(ApiResponse)]
pub enum CreateUserResponse {
    /// User Is Sucessfully Created
    #[oai(status = "200")]
    Ok(
        Json<serde_json::Value>,
        #[oai(header = "Set-Cookie")] String,
    ),
    /// User Failed To Be Created
    #[oai(status = 500)]
    ERROR(Json<serde_json::Value>),
}

#[derive(ApiResponse)]
pub enum EditUserResponse {
    /// User Is Sucessfully Created
    #[oai(status = 200)]
    Ok(Json<serde_json::Value>),
    /// User Failed To Be Created
    #[oai(status = 404)]
    Err(Json<serde_json::Value>),
}

#[derive(Object)]
pub struct UserOTPGenerationJsonResponse {
    pub user_id: u64,
    pub otp_codes: Vec<String>,
    pub expiry: Option<String>,
}

#[derive(ApiResponse)]
pub enum UserOTPGenerationResponse {
    /// Code Generation Sucessfull
    #[oai(status = 200)]
    Ok(Json<UserOTPGenerationJsonResponse>),
    /// Code Creation Failed
    #[oai(status = 500)]
    Err(Json<serde_json::Value>),
}
