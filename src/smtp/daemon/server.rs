use mio::tcp::TcpListener;
use tick;
use super::Config;
use super::connection::Connection;


/// The SMTP Server
///
pub struct Server<'a> {
    config: &'a Config,
}

impl<'a> Server<'a> {
    pub fn new(config: &'a Config) -> Server<'a> {
        Server {
            config: config,
        }
    }

    pub fn run(&mut self) -> tick::Result<()> {
        let mut tick = tick::Tick::new(|_| Connection::create(&self.config));
        let sock = try!(TcpListener::bind(&self.config.addr));
        try!(tick.accept(sock));
        info!("SMTP daemon listening on {}", &self.config.addr);
        try!(tick.run());
        Ok(())
    }
}



