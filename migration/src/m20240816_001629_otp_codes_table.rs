use sea_orm_migration::prelude::*;

use crate::m20220101_000001_users_table::Users;

/// Migration Defition
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Migration Implementation
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// OtpCodes Table Migration Up
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OtpCodes::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OtpCodes::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OtpCodes::UserId).integer().not_null())
                    .col(ColumnDef::new(OtpCodes::Code).string().not_null())
                    .col(ColumnDef::new(OtpCodes::ExpiryDate).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK_userid")
                            .from(OtpCodes::Table, OtpCodes::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    /// OtpCodes Table Migration Down
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OtpCodes::Table).to_owned())
            .await
    }
}

/// OtpCodes Table
/// Holds Codes Used For User Re-Authentication There Are Two Types:
/// - Short Term Codes
///     These Have Specifyed Expirys
/// - Recovery Codes
///     These Do Not Have Expirys
#[derive(DeriveIden)]
pub enum OtpCodes {
    Table,
    /// Internal Index Of Codes
    Id,
    /// The User The Code Authenticates
    UserId,
    /// The Code It Self
    Code,
    /// The Time & Date Of Expiry
    ExpiryDate,
}
