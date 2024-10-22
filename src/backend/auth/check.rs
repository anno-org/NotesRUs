//! # Database Checks
//!
//! This module has a single main struct [`CheckAuth`] with some usefull methods
//!
//! ```ignore
//! let check_auth = CheckAuth::new(database_connection, user_token).await;
//!
//! match check_auth {
//!     Ok(Some(check_auth)) => println!("{}", check_auth.user_id),
//!     Err(error) => println!("{error:?}")
//! }
//! ```

use derive_more::derive::Unwrap;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, Value,
};

use crate::{
    backend::auth::security_scheme::UserToken,
    entity::{clients, users},
};

/// Check Auth Pases And Retrives Data Based On [`UserToken`]
#[derive(Debug)]
pub struct CheckAuth {
    /// Connection to The Database
    database_connection: DatabaseConnection,
    /// [`clients::Column::Id`]
    pub client_id: i32,
    /// [`users::Column::Id`]
    pub user_id: i32,
    /// [`users::Model`]
    pub user_model: Option<users::Model>,
}

#[derive(Unwrap)]
#[unwrap(ref)]
pub enum AuthResult<T> {
    Found(T),
    NotFound(),
    Err(DbErr),
}

impl CheckAuth {
    /// Creation of The [`CheckAuth`] Struct And Finds
    /// [`clients::Column::UserId`] / [`users::Column::Id`]
    pub async fn new(
        database_connection: DatabaseConnection,
        user_token: UserToken,
    ) -> AuthResult<CheckAuth> {
        // Find The Client In The Database
        let client: Result<Option<clients::Model>, DbErr> = clients::Entity::find()
            .filter(clients::Column::ClientIdentifier.contains(&user_token.client_identifier))
            .filter(clients::Column::ClientSecret.contains(&user_token.client_secret))
            .one(&database_connection)
            .await;

        // Checks if Client Was Found Or Errors And Returns
        match client {
            Ok(Some(client_model)) => AuthResult::Found(CheckAuth {
                database_connection,
                client_id: client_model.id,
                user_id: client_model.user_id,
                user_model: None,
            }),
            Ok(None) => AuthResult::NotFound(),
            Err(error) => AuthResult::Err(error),
        }
    }

    /// Finds [`users::Model`]
    pub async fn find_user_model(mut self) -> AuthResult<CheckAuth> {
        // finds the user model
        let user: Result<Option<users::Model>, DbErr> = users::Entity::find_by_id(self.user_id)
            .one(&self.database_connection)
            .await;

        // Catches Potential Errors And Returns Them
        match user {
            Ok(Some(user_model)) => {
                self.user_model = Some(user_model);
                AuthResult::Found(self)
            }
            Ok(None) => AuthResult::NotFound(),
            Err(error) => AuthResult::Err(error),
        }
    }

    /// Logs The Client Access on The User
    pub async fn log_client(mut self) -> AuthResult<CheckAuth> {
        // Makes Sure The User Model is in The Struct
        if self.user_model == None {
            match self.find_user_model().await {
                AuthResult::Found(self_) => self = self_,
                AuthResult::NotFound() => return AuthResult::NotFound(),
                AuthResult::Err(error) => return AuthResult::Err(error),
            };
        }

        // Checks if User Model is in The Struct
        match self.user_model.clone() {
            Some(user_model) => {
                // Changes The MostRecentClient Column With The Curent Client
                let mut user = user_model.clone().into_active_model();
                user.set(users::Column::MostRecentClient, Value::from(self.client_id));

                // Updates The User Checks if it Failed
                match user.update(&self.database_connection).await {
                    Ok(_) => AuthResult::Found(self),
                    Err(error) => AuthResult::Err(error),
                }
            }
            None => AuthResult::NotFound(),
        }
    }
}
