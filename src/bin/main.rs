use eth_handshake::args::Args;
use eth_handshake::client::EthClient;
use eth_handshake::error::Error;

use regex::Regex;
use std::env;

pub(crate) fn parse_args() -> Result<Args, Error> {
    let args: Vec<String> = env::args().collect();
    let bin_name = args[0].clone();

    // Ensure exactly one argument is provided
    if args.len() != 2 {
        return Err(Error::InvalidArgs(
            "Check number of arguments".to_owned(),
            bin_name,
        ));
    }

    let enode_url = &args[1];
    let enode_regex = Regex::new(r"^enode://(\w+)@((?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\d+)$").unwrap();

    if let Some(captures) = enode_regex.captures(enode_url) {
        let node_id = captures.get(1).unwrap().as_str().to_owned();
        let ip = captures.get(2).unwrap().as_str().parse().map_err(|e| {
            Error::InvalidArgs(format!("Check Enode IPv4 address: {}", e), bin_name.clone())
        })?;
        let port = captures
            .get(3)
            .unwrap()
            .as_str()
            .parse::<u16>()
            .map_err(|e| Error::InvalidArgs(format!("Check Enode Port: {}", e), bin_name))?;

        return Ok(Args { node_id, ip, port });
    }

    Err(Error::InvalidArgs("Check Enode URL".to_owned(), bin_name))
}

async fn run() -> Result<(), Error> {
    let args = parse_args()?;
    tracing::info!("args {:?}", args);

    let mut client = EthClient::new(args).await?;
    client.handshake().await
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    match run().await {
        Ok(_) => {}
        Err(err) => {
            tracing::error!("{}", err);
        }
    };
}
