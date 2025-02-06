use poem_openapi::{payload::Json, ApiRequest, Object};

#[derive(Object)]
pub struct UserOTPGenerationJsonRequest {
    /// Max Of 8 Codes At One Time
    pub number_of_codes: u8,
    /// Must Follow The RFC3339 Date Standard.
    pub expirey_date: Option<String>,
}

#[derive(ApiRequest)]
pub enum UserOTPGenerationRequest {
    /// Generate Codes
    GenerateBody(Json<UserOTPGenerationJsonRequest>),
}
