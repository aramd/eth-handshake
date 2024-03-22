use crate::args::Args;
use crate::ecies::Ecies;
use crate::error::Error;
use crate::messages::{Disconnect, Hello};
use crate::utilities::node_id2pubkey;

use bytes::{Bytes, BytesMut};
use secp256k1::PublicKey;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct EthClient {
    stream: TcpStream,
    ecies: Ecies,
}

impl EthClient {
    /// Initiator connects to recipient and creates necessary keys
    pub async fn new(args: Args) -> Result<Self, Error> {
        let connection = Self::connect(SocketAddr::new(IpAddr::V4(args.ip), args.port)).await?;
        let node_pub_key = Self::build_pub_key(args.node_id)?;

        Ok(Self {
            stream: connection,
            ecies: Ecies::new(node_pub_key),
        })
    }

    /// Initiator initiates handshake. Return Error when could not complete handshake
    pub async fn handshake(&mut self) -> Result<(), Error> {
        tracing::info!("Initiating handshake protocol");

        // #1: initiator sends auth message
        let auth_msg = self.send_auth_msg().await?;

        // #5 initiator receives auth-ack and derives secrets
        let remaining = self.read_and_process_ack_msg(auth_msg).await?;

        // #6: initiator sends its first encrypted frame containing initiator Hello message
        self.send_hello_msg().await?;

        // #8: initiator receives and authenticates first encrypted frame
        let status = self.read_and_process_hello_msg(remaining).await?;
        if !status {
            tracing::error!("Handshake is failed!!!");
            return Err(Error::HandshakeFailed(
                "Disconnect or Unknown message is received",
            ));
        }

        tracing::info!("Handshake is complete!!!");
        Ok(())
    }

    async fn connect(addr: SocketAddr) -> Result<TcpStream, Error> {
        tracing::info!("Connecting to {}", addr);
        Ok(TcpStream::connect(addr).await?)
    }

    async fn send_auth_msg(&mut self) -> Result<Bytes, Error> {
        let auth_msg = self.ecies.build_auth_msg()?;
        let bytes = self.stream.write(auth_msg.as_ref()).await?;
        if bytes == 0 {
            return Err(Error::ConnectionFailed(
                "Could not send auth message to target node",
            ));
        }
        tracing::info!("Auth message is sent to target node");
        // return initial auth message for future usages
        Ok(auth_msg)
    }

    async fn read_and_process_ack_msg(&mut self, auth_msg: Bytes) -> Result<Bytes, Error> {
        // read ack from network
        let mut buffer = [0u8; 1024];
        let read_bytes = self.stream.read(&mut buffer).await?;
        tracing::debug!("buffer size = {}, data = {:?}", read_bytes, buffer);
        if read_bytes == 0 {
            tracing::info!("Ack message is not received");
            return Err(Error::ConnectionFailed(
                "Remote peer has closed the connection",
            ));
        }

        let buffer = BytesMut::from(&buffer[..read_bytes]);

        // #5: initiator receives auth-ack and derives secrets
        let remaining = self.ecies.process_ack(buffer, auth_msg)?;
        tracing::info!("Ack message is received from target node");
        tracing::debug!("remaining = {:?}", remaining);

        Ok(remaining)
    }

    async fn send_hello_msg(&mut self) -> Result<(), Error> {
        let hello_frame = self.ecies.build_hello_msg();
        if self.stream.write(hello_frame.as_ref()).await? == 0 {
            return Err(Error::ConnectionFailed(
                "Could not send hello message to target node",
            ));
        }
        tracing::info!("Hello message is sent to target node");
        Ok(())
    }

    async fn read_and_process_hello_msg(&mut self, remaining: Bytes) -> Result<bool, Error> {
        let mut buffer = BytesMut::new();
        if remaining.is_empty() {
            // read hello from Node
            let mut temp_buf = [0u8; 1024];
            let read_bytes = self.stream.read(&mut temp_buf).await?;
            tracing::debug!("buffer size = {}, data = {:?}", read_bytes, buffer);
            buffer = BytesMut::from(&temp_buf[..read_bytes])
        } else {
            // sometimes nodes sends `hello` message with `ack`
            // in that case we don't need to read anything from network
            buffer = BytesMut::from(remaining.as_ref());
        }

        // #6: initiator receives and authenticates first encrypted frame
        let frame = self.ecies.read_frame(buffer)?;
        Self::process_frame(frame)
    }

    fn build_pub_key(node_id: String) -> Result<PublicKey, Error> {
        let node_id = hex::decode(node_id).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
        Ok(node_id2pubkey(&node_id)?)
    }

    fn process_frame(mut frame: Bytes) -> Result<bool, Error> {
        let message_id = frame.split_to(1);
        let message_id = rlp::decode::<u8>(message_id.as_ref())?;

        Ok(match message_id {
            0 => {
                tracing::info!(
                    "Hello message is received from target node: {:?}",
                    rlp::decode::<Hello>(frame.as_ref())?
                );
                true
            }
            1 => {
                tracing::info!(
                    "Disconnect message is received from target node: {:?}",
                    rlp::decode::<Disconnect>(frame.as_ref())?
                );
                false
            }
            _ => {
                tracing::info!("Unknown message is received from target node: {:?}", frame);
                false
            }
        })
    }
}
