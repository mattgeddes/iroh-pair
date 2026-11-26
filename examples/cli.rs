use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh::endpoint::presets;
use iroh_pair::{initiator_connect, PairingProtocol, Payload};
use std::path::PathBuf;
use tokio::fs;

#[derive(Parser)]
#[command(name = "iroh-pair-cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Responder {
        #[arg(long)]
        save_dir: PathBuf,
    },
    Initiator {
        endpoint_id: String,
        #[arg(long)]
        files: Vec<PathBuf>,
    },
    /// Bidirectional exchange, responder side: receive a request message,
    /// reply with one, print both.
    ExchangeResponder {
        #[arg(long, default_value = "peer says hi")]
        reply: String,
    },
    /// Bidirectional exchange, initiator side: send a request message,
    /// wait for and print the reply.
    ExchangeInitiator {
        endpoint_id: String,
        #[arg(long, default_value = "hello peer")]
        message: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Responder { save_dir } => {
            let endpoint = iroh::Endpoint::bind(presets::N0).await?;
            let (protocol, mut incoming_rx) = PairingProtocol::new();
            protocol.set_local_id(endpoint.id());
            protocol.enable();
            let router = iroh::protocol::Router::builder(endpoint.clone())
                .accept(iroh_pair::ALPN, protocol.clone())
                .spawn();
            println!("Endpoint ID: {}", endpoint.id());
            println!("Waiting for pairing...");
            if let Some(mut pairing) = incoming_rx.recv().await {
                println!("SAS: {}", pairing.sas);
                println!("Confirm? (y/n)");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    pairing.finish();
                    anyhow::bail!("aborted");
                }
                let payloads = pairing.receive_batch().await?;
                fs::create_dir_all(&save_dir).await?;
                let mut seen = std::collections::HashSet::new();
                for p in payloads {
                    let name = p.safe_filename();
                    if !seen.insert(name.clone()) {
                        anyhow::bail!("duplicate output filename: {name}");
                    }
                    let path = save_dir.join(&name);
                    use tokio::fs::OpenOptions;
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .await
                        .map_err(|e| anyhow::anyhow!("cannot create {}: {}", path.display(), e))?;
                    use tokio::io::AsyncWriteExt;
                    file.write_all(&p.data).await?;
                    file.flush().await?;
                    println!("saved {} ({})", path.display(), p.mime_type);
                }
                pairing.finish();
            }
            router.shutdown().await?;
            Ok(())
        }
        Commands::Initiator { endpoint_id, files } => {
            let endpoint = iroh::Endpoint::bind(presets::N0).await?;
            let remote: iroh::EndpointId = endpoint_id.parse()?;
            let mut session = initiator_connect(&endpoint, remote).await?;
            println!("SAS: {}", session.sas);
            println!("Confirm match? (y/n)");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                anyhow::bail!("aborted");
            }
            let mut payloads = Vec::new();
            for f in files {
                let data = fs::read(&f).await?;
                let filename = f.file_name().unwrap().to_string_lossy().to_string();
                let mime = "application/octet-stream".to_string();
                payloads.push(Payload {
                    mime_type: mime,
                    filename,
                    data,
                });
            }
            session.send_batch(&payloads).await?;
            session.finish_send().await?;
            session.wait_closed().await;
            Ok(())
        }
        Commands::ExchangeResponder { reply } => {
            let endpoint = iroh::Endpoint::bind(presets::N0).await?;
            let (protocol, mut incoming_rx) = PairingProtocol::new();
            protocol.set_local_id(endpoint.id());
            protocol.enable();
            let router = iroh::protocol::Router::builder(endpoint.clone())
                .accept(iroh_pair::ALPN, protocol.clone())
                .spawn();
            println!("Endpoint ID: {}", endpoint.id());
            println!("Waiting for exchange...");
            if let Some(mut pairing) = incoming_rx.recv().await {
                println!("SAS: {}", pairing.sas);
                println!("Confirm? (y/n)");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    pairing.finish();
                    anyhow::bail!("aborted");
                }
                let request = pairing.respond_message(reply.as_bytes()).await?;
                println!("request message: {}", String::from_utf8_lossy(&request));
                println!("sent reply: {reply}");
                pairing.finish();
            }
            router.shutdown().await?;
            Ok(())
        }
        Commands::ExchangeInitiator {
            endpoint_id,
            message,
        } => {
            let endpoint = iroh::Endpoint::bind(presets::N0).await?;
            let remote: iroh::EndpointId = endpoint_id.parse()?;
            let mut session = initiator_connect(&endpoint, remote).await?;
            println!("SAS: {}", session.sas);
            println!("Confirm match? (y/n)");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                anyhow::bail!("aborted");
            }
            let reply = session.exchange_message(message.as_bytes()).await?;
            println!("sent: {message}");
            println!("reply: {}", String::from_utf8_lossy(&reply));
            session.wait_closed().await;
            Ok(())
        }
    }
}
