use std::marker::PhantomData;
use mio::tcp::TcpListener;
use tick::{self, Tick};
use super::Config;
use super::connection::Connection;
use super::handler::ServerHandler;


/// The SMTP Server
///
pub struct Server<'a, H: ServerHandler> {
    config: &'a Config,
    phantom: PhantomData<H>,
}

impl<'a, H: ServerHandler> Server<'a, H> {
    pub fn new(config: &'a Config) -> Server<'a, H> {
        Server {
            config: config,
            phantom: PhantomData,
        }
    }

    pub fn run(&mut self, handler: &H) -> tick::Result<()> {
        let mut tick = Tick::new(|_| Connection::create(handler.start()));
        let sock = try!(TcpListener::bind(&self.config.addr));
        try!(tick.accept(sock));
        info!("SMTP daemon listening on {}", &self.config.addr);
        try!(tick.run());
        Ok(())
    }
}



