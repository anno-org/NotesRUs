//! # Everything OTP Codes 🔒

use chrono::{DateTime, FixedOffset, Local};
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, ModelTrait,
    QueryFilter,
};

use crate::entity::{clients::Model, otp_codes, users};

/// # Code Generator
///
/// Generator Example Bellow
pub struct OTPGenerator {
    pub otp_code_models: Vec<otp_codes::ActiveModel>,
}

impl OTPGenerator {
    /// # OTP Code Generator
    ///
    /// ```
    /// use notes_r_us::{entity::users, backend::auth::otp_codes::OTPGenerator};
    /// use chrono::{Local, TimeDelta};
    /// use sea_orm::entity::ActiveValue;
    ///
    /// let user = users::Model {
    ///     id: 1,
    ///     username: String::from("bob_2000"),
    ///     name: String::from("bob letterman"),
    ///     most_recent_client: None,
    ///     role: None,
    ///     creation_time: Local::now().into(),
    /// };
    ///
    /// let expiry_date = (Local::now() + TimeDelta::minutes(5));
    ///
    ///
    /// let generated_code_active_models: OTPGenerator = match OTPGenerator::gen(
    ///     1,
    ///     Some(expiry_date.clone().into()),
    ///     user.clone()
    /// ) {
    ///     Ok(models) => models,
    ///     Err(err) => panic!("{}", err)
    /// };
    ///
    /// assert_eq!(
    ///     match generated_code_active_models.otp_code_models[0].user_id {
    ///         ActiveValue::Set(user_id) => user_id,
    ///         ActiveValue::Unchanged(user_id) => user_id,
    ///         ActiveValue::NotSet => panic!("UserID Not Found In Active Model")
    ///     },
    ///     user.id
    /// );
    ///
    /// assert_eq!(
    ///     match generated_code_active_models.otp_code_models[0].expiry_date {
    ///         ActiveValue::Set(user_id) => user_id,
    ///         ActiveValue::Unchanged(user_id) => user_id,
    ///         ActiveValue::NotSet => panic!("UserID Not Found In Active Model")
    ///     }.unwrap(),
    ///     expiry_date
    /// )
    /// ```
    pub fn gen(
        code_quantity: usize,
        expirey_date: Option<DateTime<FixedOffset>>,
        user_model: users::Model,
    ) -> Result<Self, &'static str> {
        let mut otp_codes_models: Vec<otp_codes::ActiveModel> = Vec::new();

        for index in 0..code_quantity {
            let gen_name: String = match names::Generator::default().next() {
                Some(gen_name) => gen_name,
                None => return Err("error creating a name!"),
            };

            let code = format!("{index}-{}-{}", gen_name, user_model.id);

            otp_codes_models.push(otp_codes::ActiveModel {
                user_id: ActiveValue::Set(user_model.id),
                code: ActiveValue::Set(code),
                expiry_date: ActiveValue::Set(expirey_date),
                ..Default::default()
            })
        }

        return Ok(Self {
            otp_code_models: otp_codes_models,
        });
    }

    /// # Apply Codes
    ///
    /// Applies The codes to the connected database to be used to authenticated user at a later
    /// point.
    pub async fn apply(
        self,
        database_connection: &DatabaseConnection,
    ) -> Result<Vec<String>, DbErr> {
        let mut otp_codes_strings: Vec<String> = Vec::new();

        for code_active_model in self.otp_code_models {
            let database_response: Result<otp_codes::Model, DbErr> =
                code_active_model.insert(database_connection).await;

            match database_response {
                Ok(code_model) => {
                    otp_codes_strings.push(code_model.code);
                }
                Err(database_err) => return Err(database_err),
            }
        }

        Ok(otp_codes_strings)
    }
}

pub enum OTPCodeValidity {
    Invalid(String),
    Valid(users::Model),
}

pub async fn otp_code_verification(
    otp_code: String,
    database_connection: &DatabaseConnection,
) -> Result<OTPCodeValidity, sea_orm::DbErr> {
    let option_model = otp_codes::Entity::find()
        .filter(otp_codes::Column::Code.contains(otp_code))
        .one(database_connection)
        .await?;

    if option_model == None {
        return Ok(OTPCodeValidity::Invalid("Code Not Found".to_string()));
    } else if option_model.clone().unwrap().expiry_date == None {
        ()
    } else if option_model.clone().unwrap().expiry_date.unwrap() < Local::now() {
        option_model
            .clone()
            .unwrap()
            .delete(database_connection)
            .await?;
        return Ok(OTPCodeValidity::Invalid("Code Is expired".to_string()));
    }

    match users::Entity::find_by_id(option_model.clone().unwrap().user_id)
        .one(database_connection)
        .await?
    {
        Some(user_model) => {
            match option_model {
                Some(model) => {
                    model.delete(database_connection).await?;
                    ()
                }
                _ => {
                    log::error!(
                        "backend::auth::otp_codes::opt_code_validation could not delete code"
                    );
                    ()
                }
            }
            return Ok(OTPCodeValidity::Valid(user_model));
        }
        None => Ok(OTPCodeValidity::Invalid("Code Not Found".to_string())),
    }
}
