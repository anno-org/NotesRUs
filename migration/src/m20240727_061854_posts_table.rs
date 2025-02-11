use sea_orm_migration::prelude::*;

use crate::m20220101_000001_users_table::Users;

/// Migration Definition
#[derive(DeriveMigrationName)]
pub struct Migration;

/// Migration Implementation
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// Post Table Migration Up
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Posts::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Posts::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Posts::UserId).integer().not_null())
                    .col(ColumnDef::new(Posts::UpVotes).integer().default(0u8))
                    .col(ColumnDef::new(Posts::DownVotes).integer().default(0u8))
                    .col(ColumnDef::new(Posts::Title).string().not_null())
                    .col(ColumnDef::new(Posts::Body).text().not_null())
                    .col(
                        ColumnDef::new(Posts::CreationTime)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Posts::EditTime).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("FK_userid")
                            .from(Posts::Table, Posts::UserId)
                            .to(Users::Table, Users::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    /// Post Table Migration Down
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Posts::Table).to_owned())
            .await
    }
}

/// Posts Table
#[derive(DeriveIden)]
pub enum Posts {
    Table,
    /// Identifyer For The Post
    Id,
    /// The User Creating The Post
    UserId,
    /// Up Votes Same Idea As Likes
    UpVotes,
    /// Down Votes Same Idea As Dislikes
    DownVotes,
    /// Title Of The Post
    Title,
    /// Post Body Field
    Body,
    /// Inital Creation Timestamp
    CreationTime,
    /// The Last Timestamp Of A Edit
    EditTime,
}
