use rlp::DecoderError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid Arguments: {0}\n\nUsage: {1} <enode_url>")]
    InvalidArgs(String, String),

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Handshake is failed: {0}")]
    HandshakeFailed(&'static str),

    #[error("Connection failed: {0}")]
    ConnectionFailed(&'static str),

    #[error("Mac mismatch: {0}")]
    MacMismatch(&'static str),

    #[error("Invalid public key {0}")]
    InvalidPublicKey(String),

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("Aes invalid length error")]
    AesInvalidLength(#[from] aes::cipher::InvalidLength),

    #[error("Rlp decoder error: {0}")]
    Decoder(#[from] DecoderError),
}
