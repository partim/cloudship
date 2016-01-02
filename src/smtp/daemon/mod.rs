//! SMTP Daemon
//!

pub use self::daemon::Daemon;

mod connection;
mod daemon;
mod server;
mod session;


//------------ Config -------------------------------------------------------

use std::net::SocketAddr;


#[derive(Debug, Clone)]
pub struct Config {
    /// The address to listen on
    addr: SocketAddr,

    /// The host name of the SMTP daemon
    hostname: Vec<u8>,

    /// The name of the software running the SMTP daemon
    systemname: Vec<u8>,

    /// Maximum message size for SIZE extension, RFC 1870
    message_size_limit: usize,

}

impl Config {
    pub fn new(addr: &SocketAddr, hostname: &[u8]) -> Config {
        Config {
            addr: addr.clone(),
            hostname: hostname.to_vec(),
            systemname: b"Cloudship".to_vec(),
            message_size_limit: 10240000,
        }
    }

    pub fn addr(&mut self, addr: &SocketAddr) -> &mut Self {
        self.addr = addr.clone();
        self
    }

    pub fn hostname(&mut self, hostname: &[u8]) -> &mut Self {
        self.hostname = hostname.to_vec();
        self
    }

    pub fn message_size_limit(&mut self, limit: usize) -> &mut Self {
        self.message_size_limit = limit;
        self
    }
}


