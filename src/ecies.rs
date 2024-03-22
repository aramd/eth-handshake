use crate::error::Error;
use crate::mac::RLPxMac;
use crate::messages::Ack;

use ethereum_types::{H128, H256};
use secp256k1::{rand::rngs::OsRng, PublicKey, Secp256k1, SecretKey};

use aes::cipher::{KeyIvInit, StreamCipher};
use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use hmac::{Hmac, Mac};
use rlp::RlpStream;
use sha2::{Digest, Sha256};

const PROTOCOL_VERSION: usize = 5;

type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

pub struct Ecies {
    /// Representing the remote node's public key.
    remote_public_key: PublicKey,

    /// Representing the secret key of the initiator.
    initiator_secret_key: SecretKey,

    /// Representing the public key of the initiator.
    initiator_public_key: PublicKey,

    /// 32 byte value representing a nonce used for cryptographic operations.
    nonce: H256,

    /// Representing the ephemeral secret key.
    ephemeral_secret_key: SecretKey,

    /// Represent derives secrets received from node
    secrets: Option<Secrets>,
}

/// This struct contains derived secrets
pub struct Secrets {
    /// A `MAC` value for egress message authentication code.
    egress_mac: RLPxMac,

    /// A `MAC` value for ingress message authentication code.
    ingress_mac: RLPxMac,

    /// A value for egress AES-256 encryption.
    egress_aes: Aes256Ctr64BE,

    /// An optional value for ingress AES-256 encryption.
    ingress_aes: Aes256Ctr64BE,
}

impl Ecies {
    /// generates initiator's public and secret keys, as well as nonce and ephemeral secret key
    pub fn new(node_pub_key: PublicKey) -> Self {
        // initiator-pubk, initiator-privkey
        let (initiator_secret_key, initiator_public_key) =
            Secp256k1::new().generate_keypair(&mut OsRng);

        // initiator-nonce
        let nonce = H256::random();

        // ephemeral-privkey
        let ephemeral_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        Self {
            remote_public_key: node_pub_key,
            initiator_secret_key,
            initiator_public_key,
            nonce,
            ephemeral_secret_key,
            secrets: None,
        }
    }

    /// Creates and returns encrypted auth message
    pub fn build_auth_msg(&self) -> Result<Bytes, Error> {
        // create unencrypted authentication message
        let unencrypted_auth = self.build_unencrypted_auth();
        let encrypted_auth = self.encrypt_auth(unencrypted_auth?)?;
        Ok(encrypted_auth)
    }

    /// Process Ack message received from recipient
    pub fn process_ack(&mut self, mut buffer: BytesMut, auth_msg: Bytes) -> Result<Bytes, Error> {
        assert!(buffer.len() >= 2);
        let payload_size = u16::from_be_bytes([buffer[0], buffer[1]]);
        let message_size = payload_size as usize + 2;

        assert!(buffer.len() >= message_size);
        let remaining_bytes = buffer.split_off(message_size);

        let ack_msg = buffer.clone().freeze();
        // Split the buffer into 2 (size), 65 (public key), 16 (iv), N (encrypted_data) and 32 (tag) parts
        let mut remaining = buffer.split_off(2);
        let remote_ephemeral_public_key = PublicKey::from_slice(remaining.split_to(65).as_ref())?;
        let iv = H128::from_slice(remaining.split_to(16).as_ref());
        let mut encrypted_data = remaining.split_to(message_size - (2 + 65 + 16 + 32));
        assert_eq!(remaining.len(), 32);
        let hmac_tag = H256::from_slice(remaining.as_ref());

        let shared_secret = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &remote_ephemeral_public_key,
                &self.initiator_secret_key,
            )[..32],
        );

        let (encryption_key, mac_key) = Self::derive_keys(&shared_secret);
        let remote_hmac_tag = Self::calculate_hmac(mac_key, &iv, &encrypted_data, payload_size)?;

        if hmac_tag != remote_hmac_tag {
            return Err(Error::MacMismatch("MAC of ack message is invalid"));
        }

        let encrypted_key = H128::from_slice(encryption_key.as_bytes());

        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data.as_mut());
        tracing::debug!("ack_body = {:?}", encrypted_data);

        // derives secrets
        self.derive_secrets(encrypted_data.freeze(), auth_msg, ack_msg)?;

        Ok(remaining_bytes.freeze())
    }

    /// Derives secrets received with Ack message
    fn derive_secrets(
        &mut self,
        auth_ack_body: Bytes,
        auth_msg: Bytes,
        ack_msg: Bytes,
    ) -> Result<(), Error> {
        let ack: Ack = rlp::decode(auth_ack_body.as_ref())?;
        // per spec implementations must ignore any mismatches in auth-vsn and ack-vsn
        tracing::debug!("ack-vsn {:?}", ack.version);

        // ephemeral-key = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        let ephemeral_shared_secret = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &ack.ephemeral_public_key,
                &self.ephemeral_secret_key,
            )[..32],
        );

        let compute_keccak256_hash = |inputs: &[&[u8]]| -> H256 {
            let mut hasher = sha3::Keccak256::new();

            for input in inputs {
                hasher.update(input);
            }

            H256::from(hasher.finalize().as_ref())
        };

        // shared-secret = keccak256(ephemeral-key || keccak256(nonce || initiator-nonce))
        let shared_secret = compute_keccak256_hash(&[
            ephemeral_shared_secret.as_ref(),
            compute_keccak256_hash(&[ack.nonce.as_ref(), self.nonce.as_ref()]).as_ref(),
        ]);

        // aes-secret = keccak256(ephemeral-key || shared-secret)
        let aes_secret =
            compute_keccak256_hash(&[ephemeral_shared_secret.as_ref(), shared_secret.as_ref()]);

        // mac-secret = keccak256(ephemeral-key || aes-secret)
        let mac_secret =
            compute_keccak256_hash(&[ephemeral_shared_secret.as_ref(), aes_secret.as_ref()]);

        // egress-mac = keccak256.init((mac-secret ^ recipient-nonce) || auth)
        let egress_mac = {
            let mut egress_mac = RLPxMac::new(mac_secret);
            egress_mac.update((mac_secret ^ ack.nonce).as_bytes());
            egress_mac.update(auth_msg.as_ref());
            egress_mac
        };

        // ingress-mac = keccak256.init((mac-secret ^ initiator-nonce) || ack)
        let ingress_mac = {
            let mut ingress_mac = RLPxMac::new(mac_secret);
            ingress_mac.update((mac_secret ^ self.nonce).as_bytes());
            ingress_mac.update(ack_msg.as_ref());
            ingress_mac
        };

        let iv = H128::default();
        let egress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());
        let ingress_aes = Aes256Ctr64BE::new(aes_secret.as_ref().into(), iv.as_ref().into());

        self.secrets = Some(Secrets {
            egress_mac,
            ingress_mac,
            egress_aes,
            ingress_aes,
        });

        Ok(())
    }

    /// Receives and authenticates encrypted frame received
    pub fn read_frame(&mut self, mut buffer: BytesMut) -> Result<Bytes, Error> {
        let mut header = buffer.split_to(16);
        let mac = H128::from_slice(buffer.split_to(16).as_ref());
        let mut frame = buffer;

        let secrets = self
            .secrets
            .as_mut()
            .expect("Secrets should be already derived");

        secrets.ingress_mac.compute_header(header.as_ref());
        if mac != secrets.ingress_mac.digest() {
            return Err(Error::MacMismatch(
                "MAC of header in Hello message is invalid",
            ));
        }

        secrets.ingress_aes.apply_keystream(header.as_mut());

        let mut frame = frame.split_to(Self::calculate_frame_size(header));
        let mut frame_body = frame.split_to(frame.len() - 16);
        let frame_mac = H128::from_slice(frame.as_ref());

        secrets.ingress_mac.compute_frame(frame_body.as_mut());

        if frame_mac == secrets.ingress_mac.digest() {
            // handshake is complete if MAC of first encrypted frame is valid on both sides
            tracing::debug!("MAC of first encrypted frame is valid in initiator side");
        } else {
            return Err(Error::MacMismatch(
                "MAC of body in Hello message is invalid",
            ));
        }

        secrets.ingress_aes.apply_keystream(frame_body.as_mut());
        Ok(frame_body.freeze())
    }

    /// Creates and returns encrypted hello message
    pub fn build_hello_msg(&mut self) -> BytesMut {
        // first byte is msg_id: 0
        let hello_body = {
            // TODO consider Hello message rlp encoding
            // also consider to improve message/frame building part
            let mut rlp_body = RlpStream::new_list(4); // or 5 with capabilities
            rlp_body.append(&PROTOCOL_VERSION);
            rlp_body.append(&"Ethereum(++)/1.0.0"); // client_version
            rlp_body.append(&0u16); // port
            rlp_body.append(&&self.initiator_public_key.serialize_uncompressed()[1..65]);

            let mut hello_body = BytesMut::default();
            hello_body.extend_from_slice(&rlp::encode(&0u8));
            hello_body.extend_from_slice(&rlp::encode(&rlp_body.out().as_ref()));
            hello_body
        };

        let mut size_buffer = BytesMut::zeroed(16);
        BigEndian::write_uint(size_buffer.as_mut(), hello_body.len() as u64, 3);

        let secrets = self
            .secrets
            .as_mut()
            .expect("Secrets should be already derived");

        secrets.egress_aes.apply_keystream(size_buffer.as_mut());
        secrets.egress_mac.compute_header(size_buffer.as_ref());

        // zero-fill frame-data to 16-byte boundary
        let mut frame_size = hello_body.len();
        if frame_size % 16 > 0 {
            frame_size = (frame_size / 16 + 1) * 16;
        }

        let mut hello_message = BytesMut::with_capacity(32 + frame_size);
        hello_message.extend_from_slice(&size_buffer);
        hello_message.extend_from_slice(secrets.egress_mac.digest().as_ref());

        let mut body = BytesMut::with_capacity(frame_size);
        body.extend_from_slice(&hello_body);

        secrets.egress_aes.apply_keystream(body.as_mut());
        secrets.egress_mac.compute_frame(body.as_mut());

        let mac = secrets.egress_mac.digest();
        body.extend_from_slice(mac.as_bytes());

        hello_message.extend_from_slice(body.as_ref());
        hello_message
    }

    fn build_unencrypted_auth(&self) -> Result<BytesMut, Error> {
        let signature = self.create_signature()?;

        // auth-body = [sig, initiator-pubk, initiator-nonce, auth-vsn, ...]
        let mut auth_body = RlpStream::new_list(4);
        auth_body.append(&signature.as_ref());
        auth_body.append(&self.initiator_public_key.serialize_uncompressed()[1..].as_ref());
        auth_body.append(&self.nonce);
        auth_body.append(&PROTOCOL_VERSION);
        Ok(auth_body.out())
    }

    fn create_signature(&self) -> Result<Bytes, Error> {
        let shared_secret = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(
                &self.remote_public_key,
                &self.initiator_secret_key,
            )[..32],
        );
        let msg = shared_secret ^ self.nonce;

        let (rec_id, sig) = Secp256k1::new()
            .sign_ecdsa_recoverable(
                &secp256k1::Message::from_digest_slice(msg.as_bytes())?,
                &self.ephemeral_secret_key,
            )
            .serialize_compact();

        let mut signature = BytesMut::zeroed(65);
        signature[..64].copy_from_slice(&sig);
        signature[64] = rec_id.to_i32() as u8;
        Ok(signature.freeze())
    }

    fn encrypt_auth(&self, mut unencrypted_auth: BytesMut) -> Result<Bytes, Error> {
        // generate a new secret and public keys
        let (random_secret_key, random_public_key) = Secp256k1::new().generate_keypair(&mut OsRng);

        let shared_secret = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&self.remote_public_key, &random_secret_key)
                [..32],
        );

        // generate a random initialization vector (IV)
        let iv = H128::random();

        // perform key derivation function
        let (encryption_key, mac_key) = Self::derive_keys(&shared_secret);

        // create an AES-128 CTR encryptor with the encryption key and IV
        let mut encryptor = Aes128Ctr64BE::new(encryption_key.as_ref().into(), iv.as_ref().into());
        encryptor.apply_keystream(unencrypted_auth.as_mut());

        // calculate the total size of the encrypted message;
        let total_size = u16::try_from(
            secp256k1::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 16 + unencrypted_auth.len() + 32,
        )
        .expect("total size of auth message cannot be bigger than max<u16>");

        let hmac_tag = Self::calculate_hmac(mac_key, &iv, &unencrypted_auth, total_size)?;

        let mut output = BytesMut::new();
        output.extend_from_slice(&total_size.to_be_bytes());
        output.extend_from_slice(&random_public_key.serialize_uncompressed());
        output.extend_from_slice(iv.as_bytes());
        output.extend_from_slice(unencrypted_auth.as_ref());
        output.extend_from_slice(hmac_tag.as_bytes());
        Ok(output.freeze())
    }

    /// Concatenation Key Derivation Function - KDF(k, 32)
    fn derive_keys(shared_key: &H256) -> (H128, H256) {
        let mut buffer = [0u8; 32];
        concat_kdf::derive_key_into::<Sha256>(shared_key.as_bytes(), &[], &mut buffer)
            .expect("derive_key_into cannot fail");

        let encryption_key = H128::from_slice(&buffer[..16]);
        let mac_key = H256::from(Sha256::digest(&buffer[16..32]).as_ref());

        (encryption_key, mac_key)
    }

    fn calculate_hmac(key: H256, iv: &H128, data: &BytesMut, size: u16) -> Result<H256, Error> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(key.as_ref())?;
        hmac.update(iv.as_bytes());
        hmac.update(data.as_ref());
        hmac.update(&size.to_be_bytes());

        let remote_hmac_tag = H256::from_slice(&hmac.finalize().into_bytes());
        Ok(remote_hmac_tag)
    }

    fn calculate_frame_size(header: BytesMut) -> usize {
        let frame_size = {
            let size = usize::try_from(BigEndian::read_uint(header.as_ref(), 3))
                .expect("It is impossible that 3 bytes int could not fit in usize");
            if size % 16 == 0 {
                size + 16
            } else {
                (size / 16 + 1) * 16 + 16
            }
        };
        frame_size
    }
}
