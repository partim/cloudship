use std::marker::PhantomData;
use std::net::SocketAddr;
use tick;
use super::Config;
use super::server::Server;
use super::handler::ServerHandler;


pub struct Daemon<H: ServerHandler> {
    config: Config,
    phantom: PhantomData<H>,
}

impl<H: ServerHandler> Daemon<H> {
    pub fn new(addr: &SocketAddr, hostname: &[u8]) -> Self {
        Daemon::configured(&Config::new(addr, hostname))
    }

    pub fn configured(config: &Config) -> Self {
        Daemon {
            config: config.clone(),
            phantom: PhantomData,
        }
    }

    pub fn run(&mut self, handler: H) -> tick::Result<()> {
        // XXX Single-thread for now
        Server::new(&self.config).run(&handler)
    }
}
