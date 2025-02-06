use sea_orm_migration::prelude::*;

use crate::m20220101_000001_users_table::Users;

/// Migration Struct Defintion
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Migration Implmentation
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Clients Table Migration Up
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Clients::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Clients::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Clients::UserId).integer().not_null())
                    .col(ColumnDef::new(Clients::ClientIdentifier).char().not_null())
                    .col(ColumnDef::new(Clients::ClientSecret).char().not_null())
                    .col(
                        ColumnDef::new(Clients::CreationTime)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK_users_id")
                            .from(Clients::Table, Clients::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    /// Clients Table Migration Down
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Clients::Table).to_owned())
            .await
    }
}

/// Clients Atached To There Refranced User.
#[derive(DeriveIden)]
pub enum Clients {
    Table,
    /// Internal Refrance To The Client.
    Id,
    /// Refrance To The User The Client Is Atached To.
    UserId,
    /// The Id The Client Uses To Refrance This.
    ClientIdentifier,
    /// The Secret Used To Authenticate.
    ClientSecret,
    /// Creation Of The Client
    CreationTime,
}
