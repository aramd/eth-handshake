use crate::utilities::node_id2pubkey;
use ethereum_types::H256;
use rlp::Decodable;
use secp256k1::PublicKey;

#[derive(Debug)]
pub struct Ack {
    pub ephemeral_public_key: PublicKey,
    pub nonce: H256,
    pub version: usize,
}

#[derive(Debug)]
pub struct Hello {
    pub version: usize,
    pub client: String,
    pub id: PublicKey,
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason: usize,
}

impl Decodable for Ack {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let ephemeral_public_key = {
            let node_id_data = rlp.val_at::<Vec<u8>>(0)?;
            node_id2pubkey(&node_id_data).map_err(|_| {
                rlp::DecoderError::Custom("Could not decode ephemeral public key in the ack")
            })?
        };

        Ok(Self {
            ephemeral_public_key,
            nonce: rlp.val_at(1)?,
            version: rlp.val_at(2)?,
        })
    }
}

impl Decodable for Hello {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let id = {
            let node_id_data = rlp.val_at::<Vec<u8>>(4)?;
            node_id2pubkey(&node_id_data).map_err(|_| {
                rlp::DecoderError::Custom(
                    "Could not decode public key (node id) in the Hello message",
                )
            })?
        };

        Ok(Self {
            version: rlp.val_at(0)?,
            client: rlp.val_at::<String>(1)?,
            id,
        })
    }
}

impl Decodable for Disconnect {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            reason: rlp.val_at(0)?,
        })
    }
}
