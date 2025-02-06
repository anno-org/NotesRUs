use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Port For The Server
    #[arg(short, long, env, default_value_t = 3000)]
    pub port: u16,

    /// What Request Origns Are Valid
    #[arg(short, long, env, default_value_t = String::from("0.0.0.0"))]
    pub origns: String,

    /// Is The Aplication Running In Kubernetes
    #[arg(short, long, env, default_value_t = String::from("localhost"))]
    pub domain: String,

    /// Weather Your Server Is Being Reached From Https:// Assumes Port (443)
    #[arg(long, env, default_value_t = false)]
    pub https: bool,

    /// Database Url (Postgres, Sqlite)
    #[arg(long, env, default_value_t = String::from("sqlite://./database.sqlite"))]
    pub database_url: String,

    /// Server Hashing Secret
    #[arg(long, env, short, default_value_t = String::from("Secure-Secret"))]
    pub server_secret: String,
}

/// Create The Server String
///
/// # Arguments
/// * `args` - Takes a allready parsed `cli::Args`
/// * `suffix - If you want a suffix e.g. `\<url\>/index.html`
/// * `http_prefix` - Allow you to add a (`http://` or `https://`) prefix depends on cli args
pub fn server_url(args: &Args, suffix: Option<String>, http_prefix: bool) -> String {
    let https: String = match args.https {
        true => String::from("https"),
        false => String::from("http"),
    };

    match http_prefix {
        true => match args.domain.as_str() {
            "localhost" => {
                return format!(
                    "{https}://{}:{}{}",
                    args.domain,
                    args.port,
                    suffix.unwrap_or(String::new())
                )
            }
            _ => {
                return format!(
                    "{https}://{}{}",
                    args.domain,
                    suffix.unwrap_or(String::new())
                )
            }
        },

        false => {
            return format!(
                "{}:{}{}",
                args.domain,
                args.port,
                suffix.unwrap_or(String::new())
            )
        } //     None => return format!("{}:{}", args.domain, args.port),
    }
}

pub fn parse() -> Args {
    let args = Args::parse();
    return args;
}
