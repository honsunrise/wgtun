#![feature(once_cell_try)]
#![feature(alloc_layout_extra)]

#[cfg_attr(target_family = "windows", path = "windows/mod.rs")]
#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
mod implement;

use std::net::SocketAddr;
use std::time::Instant;

use anyhow::Result;
use ipnet::IpNet;

#[derive(Clone, Debug)]
pub struct PeerDetail {
    /// Bitwise combination of flags
    pub flags: u32,
    /// Public key, the peer's primary identifier
    pub public_key: [u8; 32usize],
    /// Preshared key for additional layer of post-quantum resistance
    pub preshared_key: [u8; 32usize],
    /// Seconds interval, or 0 to disable
    pub persistent_keepalive: u16,
    /// Endpoint, with IP address and UDP port number
    pub endpoint: SocketAddr,
    /// Number of bytes transmitted
    pub tx_bytes: u64,
    /// Number of bytes received
    pub rx_bytes: u64,
    /// Time of the last handshake
    pub last_handshake: Instant,
    /// Number of allowed IP structs following this struct
    pub allowed_ips: Vec<IpNet>,
}

#[derive(Clone, Debug)]
pub struct InterfaceDetail {
    /// Bitwise combination of flags
    pub flags: u32,
    /// Port for UDP listen socket, or 0 to choose randomly
    pub listen_port: u16,
    /// Private key of interface
    pub private_key: [u8; 32usize],
    /// Corresponding public key of private key
    pub public_key: [u8; 32usize],
    /// Number of peer structs following this struct
    pub peers: Vec<PeerDetail>,
}

#[derive(Clone)]
pub struct PeerConfig {
    /// The peer's public key
    pub public_key: [u8; 32],

    /// A preshared key used to symmetrically encrypt data with this peer
    pub preshared_key: Option<[u8; 32]>,

    /// How often to send a keep alive packet to prevent NATs from blocking UDP packets
    ///
    /// Set to None if no keep alive behavior is wanted
    pub keep_alive: Option<u16>,

    /// The address this peer is reachable from using UDP across the internet
    pub endpoint: SocketAddr,

    /// The set of [`IpNet`]'s that define for which a peer will route traffic.
    ///
    /// Any packet from the given peer with a source IP address which is not
    /// listed in `allowed_ips` will be discarded!
    pub allowed_ips: Vec<IpNet>,
}

pub trait Interface {
    fn set_link_ip_address(&self, ip: IpNet, mtu: u32) -> Result<()>;
    fn up(&self) -> Result<()>;
    fn down(&self) -> Result<()>;

    fn update_private_key(&self, private_key: [u8; 32]) -> Result<()>;
    fn get_public_key(&self) -> Result<[u8; 32]>;
    fn update_listen_port(&self, port: u16) -> Result<()>;
    fn get_detail(&self) -> Result<InterfaceDetail>;

    fn upsert_peer(&self, peer: PeerConfig) -> Result<()>;
    fn remove_peer(&self, public_key: [u8; 32]) -> Result<()>;
    fn clear_peers(&self) -> Result<()>;
}

#[cfg(target_family = "windows")]
pub use self::implement::init;
pub use self::implement::{create_interface, open_interface};
