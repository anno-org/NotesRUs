use sea_orm_migration::{prelude::*, sea_orm::DbBackend};

use crate::m20240726_065639_clients_table::Clients;

/// Migration Defition
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Migration Implementation
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// User Table Migration Up
    /// This table is special as it refrances a table that dosent exist sqlite likes it to make foregin key here. However postgres doesn't this is why theres a foreign key migration that runs last.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            return manager
                .create_table(
                    Table::create()
                        .table(Users::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Users::Id)
                                .integer()
                                .not_null()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Users::Username).string().not_null())
                        .col(ColumnDef::new(Users::Name).string())
                        .col(ColumnDef::new(Users::MostRecentClient).integer())
                        .col(ColumnDef::new(Users::Role).integer().default(0u8))
                        .col(
                            ColumnDef::new(Users::CreationTime)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .foreign_key(
                            ForeignKey::create()
                                .name("FK_most_recent_client")
                                .from(Users::Table, Users::MostRecentClient)
                                .to(Clients::Table, Clients::Id),
                        )
                        .to_owned(),
                )
                .await;
        } else {
            return manager
                .create_table(
                    Table::create()
                        .table(Users::Table)
                        .if_not_exists()
                        .col(
                            ColumnDef::new(Users::Id)
                                .integer()
                                .not_null()
                                .auto_increment()
                                .primary_key(),
                        )
                        .col(ColumnDef::new(Users::Username).string().not_null())
                        .col(ColumnDef::new(Users::Name).string().not_null())
                        .col(ColumnDef::new(Users::MostRecentClient).integer())
                        .col(ColumnDef::new(Users::Role).integer().default(0u8))
                        .col(
                            ColumnDef::new(Users::CreationTime)
                                .timestamp_with_time_zone()
                                .not_null(),
                        )
                        .to_owned(),
                )
                .await;
        }
    }

    /// User Table Migration Down
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

/// The Central Table Users Holds all User Details
#[derive(DeriveIden)]
pub enum Users {
    Table,
    /// The Internal Identifyer For The User
    Id,
    /// The Predecied User Name
    Username,
    /// The User Decied Name
    Name,
    /// The Last Used Client By `Client::Id`
    MostRecentClient,
    /// Role Id For Future Use
    Role,
    /// Time Of user Creation
    CreationTime,
}
