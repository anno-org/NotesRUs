use crate::{
    backend::{
        auth::security_scheme::{ServerSecret, UserToken},
        requests::post::{PostCreation, PostEdition, PostSelection},
        responses::post::{
            PostCreationResponse, PostDeletionResponse, PostEditionResponse, PostGetResponse,
            PostResponseSuccess,
        },
    },
    entity::{clients, posts, users},
};
use auth::{
    check::{AuthResult, CheckAuth},
    otp_codes::{self, otp_code_verification, OTPCodeValidity},
};
use chrono::{DateTime, FixedOffset, Local, ParseResult};
use jwt::SignWithKey;
use names::{Generator, Name};
use poem::web::Data;
use poem_openapi::{
    param::{Header, Query},
    payload::{Json, PlainText},
    OpenApi, Tags,
};
use requests::{post::PostContentBody, user::{UserOTPGenerationJsonRequest, UserOTPGenerationRequest}};
use responses::user::{
    UserOTPGenerationJsonResponse, UserOTPGenerationResponse, UserOTPUseResponse,
};
use sea_orm::ActiveModelTrait;
use sea_orm::Set as DataBaseSet;
use sea_orm::{DatabaseConnection, IntoActiveModel};
use serde_json::json;
use uuid::Uuid;

use self::auth::{check, security_scheme::ApiSecurityScheme};

use super::cli::Args;

pub mod auth;
pub mod requests;
pub mod responses;

#[derive(Tags)]
pub enum ApiTags {
    /// These routes are responsible for the creation and mangment of user accounts.
    User,
    /// Route Redirects To Docs
    Redirects,
    /// Post Managemet
    Post,
}

pub struct Api {
    pub database_connection: DatabaseConnection,
    pub args: Args,
}

// for development pruposes only should be removed
#[allow(unused_variables)]

/// Notes R Us API
///
/// # The Rust Documentation can be found at
/// [docs.rs/notes_r_us/latest/notes_r_us/backend](https://docs.rs/notes_r_us/latest/notes_r_us/backend)
#[OpenApi]
impl Api {
    /// Redirect The Index Path
    ///
    /// # Redirects
    /// This Redirects the user from `.../` to `.../docs`
    #[oai(path = "/", method = "get", tag = ApiTags::Redirects)]
    pub async fn index(&self) -> responses::Redirect {
        responses::Redirect::Response("/api/docs".to_string())
    }

    /// User Creation
    ///
    /// # User Creation
    /// This route is to be used to create a new user.
    ///
    /// Name param will be used on the data base side witch has not been implemted yet...
    #[oai(path = "/user/creation", method = "get", tag = ApiTags::User)]
    pub async fn create_user(
        &self,
        server_secret: Data<&ServerSecret>,
        #[oai(name = "Name")] name: Header<Option<String>>,
        #[oai(name = "ClientName")] client_name: Header<Option<String>>,
    ) -> responses::user::CreateUserResponse {
        // initlises the client object minuns the username
        let mut client = UserToken {
            client_secret: Uuid::new_v4()
                .sign_with_key(&server_secret.clone())
                .expect("Could Not Sign Client Secret"),
            client_identifier: match client_name.0 {
                Some(client_name) => client_name,
                None => Generator::with_naming(Name::Plain)
                    .next()
                    .unwrap()
                    .to_string(),
            },
            ..Default::default()
        };

        // user with out the username that includes there id `{username}` not `{username}-{id}`
        let user: users::ActiveModel = users::ActiveModel {
            username: sea_orm::ActiveValue::set(
                Generator::with_naming(Name::Plain).next().unwrap(),
            ),
            name: match name.clone() {
                Some(name) => sea_orm::ActiveValue::set(name.into()),
                None => sea_orm::ActiveValue::not_set(),
            },
            most_recent_client: sea_orm::ActiveValue::not_set(),
            role: sea_orm::ActiveValue::not_set(),
            creation_time: sea_orm::ActiveValue::set(Local::now().into()),
            ..Default::default()
        };

        // applies the user active model
        let user: Result<users::Model, sea_orm::DbErr> =
            user.insert(&self.database_connection).await;

        // updates the username to be unique by adding the id of the user to the end `{username}-{id}`
        let user: Result<users::Model, sea_orm::DbErr> = match user {
            Ok(user_model) => {
                client.user_name = format!("{}-{}", user_model.username, user_model.id);
                let mut user: users::ActiveModel = user_model.clone().into_active_model();
                user.set(users::Column::Username, client.user_name.clone().into());
                user.update(&self.database_connection).await
            }
            Err(user_err) => Err(user_err),
        };

        let client_table: Result<clients::Model, sea_orm::DbErr> = match user {
            Ok(user_model) => {
                clients::ActiveModel {
                    user_id: sea_orm::ActiveValue::Set(user_model.id),
                    client_identifier: sea_orm::ActiveValue::Set(client.client_identifier.clone()),
                    client_secret: sea_orm::ActiveValue::Set(client.client_secret.clone()),
                    creation_time: sea_orm::ActiveValue::Set(Local::now().into()),
                    ..Default::default()
                }
                .insert(&self.database_connection)
                .await
            }
            Err(user_err) => Err(user_err),
        };

        // catches any error prone db code and returns to the user
        match client_table {
            Err(error) => {
                return responses::user::CreateUserResponse::ERROR(Json(
                    json!({"error" : format!("{error:?}"), "code":500}),
                ));
            }

            Ok(_) => {
                return responses::user::CreateUserResponse::Ok(
                    Json(json!({
                        "message": format!("{} account has been created", name.clone().unwrap_or("".to_string())).as_str()
                    })),
                    client.to_cookie_string(&self.args, server_secret.0.clone(), None),
                );
            }
        }
    }

    /// User Edit
    ///
    /// # Edit Name
    /// This route is to remove or change the name of the user note this is not the same as
    /// username.
    #[oai(path = "/user/edit", method = "get", tag = ApiTags::User)]
    pub async fn wow(
        &self,
        auth: ApiSecurityScheme,
        #[oai(name = "NewName")] username: Header<String>,
    ) -> responses::user::EditUserResponse {
        println!(
            "{:?}",
            check::CheckAuth::new(self.database_connection.clone(), auth.0.clone())
                .await
                .unwrap_found()
                .log_client()
                .await
                .unwrap_found()
        );

        match check::CheckAuth::new(self.database_connection.clone(), auth.0.clone()).await {
            AuthResult::Found(check_auth) => match check_auth.find_user_model().await {
                AuthResult::Found(check_auth) => match check_auth.log_client().await {
                    AuthResult::Found(check_auth) => {
                        let mut user = check_auth.user_model.clone().unwrap().into_active_model();
                        user.name = DataBaseSet(username.0.clone());
                        user.update(&self.database_connection).await.unwrap();

                        responses::user::EditUserResponse::Ok(Json(json!({
                            "message":
                                format!(
                                    "User {}'s name was updated to {}",
                                    check_auth.user_model.unwrap().username,
                                    username.0
                                )
                        })))
                    }
                    AuthResult::Err(error) => responses::user::EditUserResponse::Err(Json(
                        json!({"message": "User recent client failed to be loged", "error": {"code": 500u16, "message": format!("{error:?}")}}),
                    )),
                    AuthResult::NotFound() => responses::user::EditUserResponse::Err(Json(
                        json!({"message": "error yet to be caught"}),
                    )),
                },
                AuthResult::Err(error) => responses::user::EditUserResponse::Err(Json(
                    json!({"message": "Could not find user in database", "error": {"code": 500u16, "message": format!("{error:?}")}}),
                )),
                AuthResult::NotFound() => responses::user::EditUserResponse::Err(Json(
                    json!({"message": "error yet to be caught"}),
                )),
            },
            AuthResult::Err(error) => responses::user::EditUserResponse::Err(Json(
                json!({"message": "User failed to authenticate", "error": {"code": 500u16, "message": format!("{error:?}")}}),
            )),
            AuthResult::NotFound() => responses::user::EditUserResponse::Err(Json(
                json!({"message": "error yet to be caught"}),
            )),
        }
    }

    /// # OTP Code Generator/Creator
    #[oai(path = "/user/otp/generate", method = "post", tag = ApiTags::User)]
    pub async fn otp_generate(
        &self,
        auth: ApiSecurityScheme,
        req: UserOTPGenerationRequest,
    ) -> UserOTPGenerationResponse {
        let request_body: UserOTPGenerationJsonRequest = match req {
            UserOTPGenerationRequest::GenerateBody(body) => body.0,
        };

        //FIX: need to change this to some how not use a hanging refrance to
        //make the variable to be avilable in this scope.
        let mut expiry_stamp: Option<DateTime<FixedOffset>> = None;

        match request_body.expirey_date {
            Some(ref expiry_date) => {
                let stamp: ParseResult<DateTime<FixedOffset>> =
                    DateTime::parse_from_rfc2822(expiry_date.as_str());

                match stamp {
                    Err(error) => {
                        return UserOTPGenerationResponse::Err(Json(
                            json!({"message": "TimeStamp Could Not Be Parsed Make Sure Your Using `rfc2822`", "error": {"code": 500u16, "message": error.to_string()}}),
                        ));
                    }
                    Ok(_) => (),
                };
                expiry_stamp = Some(stamp.unwrap());
            }
            None => expiry_stamp = None,
        };

        //FIX: need to change this to some how not use a hanging refrance to
        //make the variable to be avilable in this scope.
        let mut user_model: Option<users::Model> = None;

        match CheckAuth::new(self.database_connection.clone(), auth.0).await {
            AuthResult::Found(auth) => match auth.find_user_model().await {
                AuthResult::Found(found_user_model) => user_model = found_user_model.user_model,
                AuthResult::NotFound() => {
                    return UserOTPGenerationResponse::Err(Json(json!({"Auth_error": ""})))
                }
                AuthResult::Err(error) => {
                    return UserOTPGenerationResponse::Err(Json(json!({"Auth_error": ""})))
                }
            },
            AuthResult::NotFound() => {
                return UserOTPGenerationResponse::Err(Json(json!({"Auth_error": ""})))
            }
            AuthResult::Err(error) => {
                return UserOTPGenerationResponse::Err(Json(json!({"Auth_error": ""})))
            }
        };

        if let Some(user_model) = user_model {
            match otp_codes::OTPGenerator::gen(
                request_body.number_of_codes.into(),
                expiry_stamp,
                &user_model,
            )
            .unwrap()
            .apply(&self.database_connection)
            .await
            {
                Ok(codes) => {
                    return UserOTPGenerationResponse::Ok(Json(UserOTPGenerationJsonResponse {
                        user_id: user_model.id as u64,
                        otp_codes: codes,
                        expiry: request_body.expirey_date,
                    }))
                }
                Err(error) => {
                    return UserOTPGenerationResponse::Err(Json(
                        json!({"Message": "Database Error", "error": {"code": 500u16, "message": error.to_string()}}),
                    ))
                }
            }
        } else {
            return UserOTPGenerationResponse::Err(Json(json!({
                "Message": "Database Error",
                "error": {
                    "code": 500u16,
                    "message": "User/user_model Was Not Found"
                }
            })));
        }
    }

    /// OTP Code Authentication
    #[oai(path = "/user/otp/authenticate", method = "post", tag = ApiTags::User)]
    pub async fn otp_authenticate(
        &self,
        server_secret: Data<&ServerSecret>,
        code: Query<String>,
        client_identifier: Query<String>,
    ) -> UserOTPUseResponse {
        match otp_code_verification(code.0, &self.database_connection).await {
            Ok(OTPCodeValidity::Valid(user_model)) => {
                let client_token = UserToken {
                    client_identifier: client_identifier.0.clone(),
                    client_secret: Uuid::new_v4().to_string(),
                    user_name: user_model.username,
                    ..Default::default()
                };

                let client = clients::ActiveModel {
                    user_id: sea_orm::ActiveValue::Set(user_model.id),
                    client_identifier: sea_orm::ActiveValue::Set(client_identifier.0),
                    client_secret: sea_orm::ActiveValue::Set(client_token.client_secret.clone()),
                    creation_time: sea_orm::ActiveValue::Set(client_token.creation_date.into()),
                    ..Default::default()
                };
                match client.insert(&self.database_connection).await {
                    Ok(_) => UserOTPUseResponse::Ok(
                        Json(json!({})),
                        client_token.to_cookie_string(&self.args, server_secret.0.clone(), None),
                    ),
                    Err(error) => UserOTPUseResponse::Err(Json(responses::ErrorMessage {
                        message: "Database Failure To Create Client".to_string(),
                        error: responses::Error {
                            message: error.to_string(),
                            code: 500,
                        },
                    })),
                }
            }
            Err(error) => UserOTPUseResponse::Err(Json(responses::ErrorMessage {
                message: "Database Failure On Fetch Of Code".to_string(),
                error: responses::Error {
                    code: 500,
                    message: error.to_string(),
                },
            })),
            Ok(OTPCodeValidity::Invalid(invalid_error)) => {
                UserOTPUseResponse::Invalid(Json(responses::ErrorMessage {
                    message: "Code Was Invalid".to_string(),
                    error: responses::Error {
                        code: 401,
                        message: invalid_error,
                    },
                }))
            }
        }
    }

    /// Create A New Post/Note
    ///
    /// This route is to create A new post and returning a adquite response to user.
    #[oai(path = "/post/create", method = "put", tag = ApiTags::Post)]
    pub async fn post_create(
        &self,
        server_secret: Data<&ServerSecret>,
        auth: ApiSecurityScheme,
        req: PostCreation,
    ) -> PostCreationResponse {
        let request_body: PostContentBody = match req {
            PostCreation::CreatePost(body) => body.0,
        };

        let user_info: CheckAuth = match CheckAuth::new(self.database_connection.clone(), auth.0).await {
            AuthResult::Found(check_auth_struct) => check_auth_struct,
            AuthResult::NotFound() => {
                return PostCreationResponse::Forbiden
            },
            AuthResult::Err(db_err) => {
                return PostCreationResponse::Err(
                    PlainText(
                        db_err.to_string()
                    )
                )
            }
        }.log_client()
            .await
            .unwrap_found().find_user_model().await.unwrap_found();

        let post: Result<posts::Model, sea_orm::DbErr> = posts::ActiveModel {
            user_id: sea_orm::ActiveValue::Set(user_info.user_id),
            title: sea_orm::ActiveValue::Set(request_body.title),
            body: sea_orm::ActiveValue::Set(request_body.body),
            creation_time: sea_orm::ActiveValue::Set(Local::now().into()),
            ..Default::default()
        }.insert(&self.database_connection).await;

        match post {
            Ok(model) => {
                return PostCreationResponse::PostCreated(Json(PostResponseSuccess {
                    username: match user_info.user_model {
                        Some(user_model) => user_model.username,
                        None => {
                            return PostCreationResponse::Err(
                                PlainText(
                                    "DBERR: Failed To Find The Username/Model".to_string()
                                )
                            )
                        },
                    },
                    post_id: model.id
                }))
            },
            Err(db_err) => {
                PostCreationResponse::Err(PlainText(db_err.to_string()))
            }
        }
    }

    /// Edit An Exsiting Post/Note
    ///
    /// This route is to edit an existing post by `PostId`.
    #[oai(path = "/post/edit", method = "post", tag = ApiTags::Post)]
    pub async fn post_edit(
        &self,
        auth: ApiSecurityScheme,
        #[oai(name = "PostId")] post_id: Header<String>,
        req: PostEdition,
    ) -> PostEditionResponse {
        PostEditionResponse::Forbiden
    }

    /// Delete A Post/Note
    ///
    /// This route is to delete a note by `PostId`.
    #[oai(path = "/post/delete", method = "delete", tag = ApiTags::Post)]
    pub async fn post_delete(
        &self,
        auth: ApiSecurityScheme,
        req: PostSelection,
    ) -> PostDeletionResponse {
        PostDeletionResponse::Forbiden
    }

    /// Get A Post/Note
    ///
    /// This route gets posts/notes by id.
    #[oai(path = "/post/get", method = "get", tag = ApiTags::Post)]
    pub async fn post_get(&self, #[oai(name = "PostId")] post_id: Query<u64>) -> PostGetResponse {
        PostGetResponse::PostNotFound
    }
}
