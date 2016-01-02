use std::net::SocketAddr;
use tick;
use super::Config;
use super::server::Server;


pub struct Daemon {
    config: Config,
}

impl Daemon {
    pub fn new(addr: &SocketAddr, hostname: &[u8]) -> Daemon {
        Daemon::configured(&Config::new(addr, hostname))
    }

    pub fn configured(config: &Config) -> Daemon {
        Daemon {
            config: config.clone(),
        }
    }

    pub fn run(&mut self) -> tick::Result<()> {
        // XXX Single-thread for now
        Server::new(&self.config).run()
    }
}
