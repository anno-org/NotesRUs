use poem_openapi::{payload::Json, ApiRequest, Object};

/// Default Value For `title` In [`PostCreationBody`]
fn title_default() -> String {
    "Title".to_string()
}

/// Default Value For `body` In [`PostCreationBody`]
fn body_default() -> String {
    "BodyContent".to_string()
}

/// Default Value For `post_id` in [`PostDeletionBody`]
fn post_id_default() -> u64 {
    123u64
}

/// Body of the Post/Note Creation Request
#[derive(Object)]
pub struct PostContentBody {
    /// The Title Of You Post/Note
    #[oai(default = "title_default")]
    pub title: String,
    /// The Main Body/Content Of Your Post/Note
    #[oai(default = "body_default")]
    pub body: String,
}

/// Body Of Post/Note A Select Type Request
#[derive(Object)]
pub struct PostSelectionBody {
    /// Post/Note You Want To Be Select
    #[oai(default = "post_id_default")]
    post_id: u64,
}

/// Post/Note Creation
#[derive(ApiRequest)]
pub enum PostCreation {
    /// Json Request Body
    CreatePost(Json<PostContentBody>),
}

/// Post/Note Edition
#[derive(ApiRequest)]
pub enum PostEdition {
    /// Json Request Body
    EditPost(Json<PostContentBody>),
}

/// Post/Note Selection
#[derive(ApiRequest)]
pub enum PostSelection {
    /// Requests Json Body
    DeletePost(Json<PostSelectionBody>),
}
