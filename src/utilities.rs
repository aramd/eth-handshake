use secp256k1::PublicKey;

/// Computes public key from recipient id.
pub fn node_id2pubkey(node_id: &[u8]) -> Result<PublicKey, secp256k1::Error> {
    // uncompressed (65 bytes, header byte 0x04)
    // https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1.h#L432
    let mut uncompressed_pubkey = [4u8; 65];
    uncompressed_pubkey[1..].copy_from_slice(node_id);
    PublicKey::from_slice(&uncompressed_pubkey)
}
