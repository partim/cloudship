use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use mio::tcp::TcpListener;
use openssl::ssl::{self, SslContext};
use tick::{self, Tick};
use super::connection::Connection;
use super::handler::ServerHandler;
use net::tls::StartTlsListener;


/// The SMTP Server
///
pub struct Server<H: ServerHandler> {
    addr: SocketAddr,
    ssl_context: Arc<SslContext>,
    phantom: PhantomData<H>,
}

impl<H: ServerHandler> Server<H> {
    pub fn new(addr: SocketAddr, ssl_context: SslContext) -> Server<H> {
        Server {
            addr: addr,
            ssl_context: Arc::new(ssl_context),
            phantom: PhantomData,
        }
    }

    pub fn run(&mut self, handler: H) -> tick::Result<()> {
        let mut tick = Tick::new(|_| Connection::create(handler.start()));
        let sock = try!(TcpListener::bind(&self.addr));
        try!(tick.accept(sock));
        info!("SMTP daemon listening on {}", &self.addr);
        try!(tick.run());
        Ok(())
    }
}

