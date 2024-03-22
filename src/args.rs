use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Args {
    /// The node_id component of an Enode URL is typically represented as the node's public key.
    pub node_id: String,

    /// Node's TCP ip.
    pub ip: Ipv4Addr,

    /// Node's TCP port.
    pub port: u16,
}
