use hmac::{Hmac, Mac};
use notes_r_us::{
    backend::{auth::security_scheme::ServerSecret, Api},
    cli,
};
use poem::{
    endpoint::StaticFilesEndpoint, listener::TcpListener, middleware::Cors, middleware::Tracing,
    EndpointExt, Route, Server,
};
use poem_openapi::OpenApiService;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use std::{env, io};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use notes_r_us_migrations::{Migrator, MigratorTrait};

#[tokio::main]
async fn main() -> io::Result<()> {
    // Parse the Args
    let args = cli::parse();

    // Database Connection
    let mut database_connection_config = ConnectOptions::new(&args.database_url);

    database_connection_config.sqlx_logging_level(log::LevelFilter::Error);

    let database_connection: DatabaseConnection =
        Database::connect(database_connection_config).await.unwrap();

    // Migration run
    let _ = Migrator::up(&database_connection, None).await;

    // Hmac Signing Key
    let server_key: ServerSecret = Hmac::new_from_slice(args.server_secret.as_bytes())
        .expect("The Server Secret Is Too Short This Is Insecure");

    // Set up tracing subscriber for logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    println!("{}", cli::server_url(&args, Some(String::from("/")), true));

    // Configure CORS settings
    let cors = Cors::new()
        .allow_origins(vec![
            cli::server_url(&args, None, true).as_str(),
            "http://localhost:5173",
        ])
        .allow_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allow_headers(vec![
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "Content-Disposition",
            "*",
        ])
        .allow_credentials(true)
        .expose_headers(vec![
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "Content-Disposition",
            "*",
        ]);

    // Create the API service
    let api_service = OpenApiService::new(
        Api {
            args: args.clone(),
            database_connection,
        },
        "Notes R Us API Documentation",
        env!("CARGO_PKG_VERSION"),
    )
    // Set up the application routes
    .server(cli::server_url(&args, Some(String::from("/api/")), true));
    let ui_docs_swagger = api_service.swagger_ui();

    // Web Ui
    let web_ui = StaticFilesEndpoint::new(env::current_dir().unwrap().join("notes_r_us_ui/dist"))
        .index_file("index.html");

    // Apply CORS middleware to the routes
    let app = Route::new()
        .nest(
            "/api",
            Route::new()
                .nest("/", api_service)
                .nest("/docs", ui_docs_swagger)
                .with(cors)
                .with(Tracing)
                .data(server_key),
        )
        .nest("/", web_ui);
    // Start the server
    Server::new(TcpListener::bind(format!(
        "{}:{}",
        &args.origns, &args.port
    )))
    .run(app)
    .await
}
