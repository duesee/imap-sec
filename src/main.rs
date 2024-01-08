mod bisect;
mod exploit;
mod learn;

use std::net::SocketAddr;

use argh::FromArgs;
use tracing::{info, Level};
use tracing_subscriber::{filter::Directive, EnvFilter};

#[derive(FromArgs, PartialEq, Debug)]
/// imap-sec.
struct Arguments {
    #[argh(subcommand)]
    subcommand: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand)]
enum SubCommand {
    MaxTag(MaxTag),
    MaxLiteral(MaxLiteral),
    AllowedTag(AllowedTag),
    OutOfMemory(OutOfMemory),
}

/// Learn max tag length (through NOOP command)
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "max_tag")]
struct MaxTag {
    /// host
    #[argh(positional)]
    host: SocketAddr,

    /// min
    #[argh(positional)]
    min: u64,

    /// max
    #[argh(positional)]
    max: u64,
}

/// Learn max literal length (through user astring in LOGIN command)
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "max_literal")]
struct MaxLiteral {
    /// host
    #[argh(positional)]
    host: SocketAddr,

    /// min
    #[argh(positional)]
    min: u64,

    /// max
    #[argh(positional)]
    max: u64,
}

/// Learn allowed tag characters (through NOOP command)
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "allowed_tag")]
struct AllowedTag {
    /// host
    #[argh(positional)]
    host: SocketAddr,
}

/// Try to bring server OOM via SEARCH command. WARNING: Don't use in production.
#[derive(FromArgs, PartialEq, Debug)]
#[argh(subcommand, name = "oom")]
struct OutOfMemory {
    /// host
    #[argh(positional)]
    host: SocketAddr,

    /// username
    #[argh(positional)]
    username: String,

    /// password
    #[argh(positional)]
    password: String,

    /// chunk size
    #[argh(positional)]
    chunk_size: u32,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize tracing
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(Directive::from(Level::TRACE).to_string()));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .without_time()
        .init();

    let args: Arguments = argh::from_env();
    info!(?args);

    match args.subcommand {
        SubCommand::MaxTag(MaxTag { host, min, max }) => {
            let max_tag = learn::max_tag(&host, min, max).await;
            println!("Maximum tag length: {max_tag}");
        }
        SubCommand::MaxLiteral(MaxLiteral { host, min, max }) => {
            let max_literal = learn::max_literal(&host, min, max).await;
            println!("Maximum literal length: {max_literal} (0x{max_literal:x})");
        }
        SubCommand::AllowedTag(AllowedTag { host }) => {
            let allowed_tag_characters = learn::allowed_tag(&host).await;
            println!("Allowed tag characters:");
            for (dec, char, result) in allowed_tag_characters {
                println!("{dec}: \"A[{char}]\" => {:?}", result.unwrap());
            }
        }
        SubCommand::OutOfMemory(OutOfMemory {
            host,
            username,
            password,
            chunk_size,
        }) => {
            exploit::oom(&host, &username, &password, chunk_size).await;
        }
    }
}
