use poem_openapi::{
    payload::{Attachment, Json, PlainText},
    types::multipart::Upload,
    ApiResponse, Multipart, Object,
};

pub mod post;
pub mod user;

/// Error Sub Struct
#[derive(Object)]
pub struct Error {
    /// HTTP Error Code
    pub code: u16,
    /// Raw Error Messge
    pub message: String,
}

/// Global Error Response Struct
#[derive(Object)]
pub struct ErrorMessage {
    /// Simplifyed Error Message
    pub message: String,
    /// Advanced Error Explaination
    pub error: Error,
}

#[derive(Debug, ApiResponse)]
pub enum GetFileResponse {
    #[oai(status = 200)]
    Ok(Attachment<Vec<u8>>),
    /// File not found
    #[oai(status = 404)]
    NotFound,
}

#[derive(Debug, ApiResponse)]
pub enum ViewFileResponse {
    #[oai(status = 200)]
    Ok(PlainText<String>),
    /// File not found
    #[oai(status = 404)]
    NotFound,
}

#[derive(Debug, ApiResponse)]
pub enum DeleteFileResponse {
    #[oai(status = 200)]
    Ok(Json<String>),
    /// File not found
    #[oai(status = 404)]
    NotFound,
}

#[derive(Debug, Multipart)]
pub struct UploadPayload {
    pub file: Upload,
}

#[derive(poem_openapi::ApiResponse)]
pub enum Redirect {
    #[oai(status = 302)]
    Response(#[oai(header = "Location")] String),
}
