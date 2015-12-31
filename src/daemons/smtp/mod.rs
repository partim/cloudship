//! SMTP Daemon
//!

use std::fmt::Debug;
use std::mem;
use std::net::SocketAddr;
use bytes;
use bytes::{Bytes, ByteStr};
use mio::{TryRead, TryWrite};
use mio::tcp::{TcpListener, TcpStream};
use tick::{self, Interest, Result};


//------------ Daemon -------------------------------------------------------

/// The SMTP Daemon
///
pub struct Daemon {
    addr: SocketAddr,
}

impl Daemon {
    pub fn new(addr: &SocketAddr) -> Daemon {
        Daemon {
            addr: addr.clone(),
        }
    }

    pub fn run(&mut self) -> Result<()> {
        let mut tick = tick::Tick::new(|_| Connection::accept());
        let sock = try!(TcpListener::bind(&self.addr));
        try!(tick.accept(sock));
        info!("SMTP daemon listening on {}", &self.addr);
        try!(tick.run());
        Ok(())
    }
}


//------------ Connection ---------------------------------------------------

/// A connection to an SMTP daemon
///
struct Connection {
    state: State,
}

impl Connection {
    fn new() -> Connection {
        Connection {
            state: State::InExchange(
                       Box::new(
                          Response::idle(b"220 localhost.local ESMTP\r\n"))),
        }
    }

    fn accept() -> (Connection, Interest) {
        let conn = Connection::new();
        let interest = conn.interest();
        (conn, interest)
    }

    fn interest(&self) -> Interest {
        match self.state {
            State::Idle(..) => Interest::Read,
            State::InExchange(ref exchange) => exchange.interest(),
            State::Closing(..) => Interest::Read,
            State::Closed => Interest::Remove,
        }
    }

    fn start_exchange(buf: &[u8]) -> State {
        State::InExchange(Box::new(
            if buf.starts_with(b"QUIT\r\n") {
                Response::closed(b"221 2.0.0 Bye\r\n")
            }
            else {
                Response::idle(
                    b"502 5.0.2 Command not implemented\r\n")
            }
        ))
    }
}

impl tick::Protocol<TcpStream> for Connection {
    fn on_readable(&mut self, transport: &mut TcpStream) -> Interest {
        let next = match self.state {
            State::Idle(ref mut buf) => {
                read_line(transport, buf, |buf| Self::start_exchange(buf))
            },
            State::InExchange(ref mut exchange) => {
                exchange.on_readable(transport)
            },
            State::Closing(ref mut buf) => {
                read_line(transport, buf, |buf| {
                    State::InExchange(Box::new(
                        if buf.starts_with(b"QUIT\r\n") {
                            Response::closed(b"221 2.0.0 Bye")
                        }
                        else {
                            Response::closing(
                                b"503 5.0.3 Bad sequence of commands")
                        }
                    ))
                })
            },
            State::Closed => unreachable!()
        };

        debug!("New state: {:?}", next);
        
        match next {
            Some(state) => self.state = state,
            None => { }
        }

        self.interest()
    }

    fn on_writable(&mut self, transport: &mut TcpStream) -> Interest {
        let next = match self.state {
            State::InExchange(ref mut exchange) => {
                exchange.on_writable(transport)
            },
            _ => unreachable!()
        };

        match next {
            Some(state) => self.state = state,
            None => { }
        }

        self.interest()
    }

    fn on_error(&mut self, err: tick::Error) {
        debug!("Error on SMTP connection: {:?}", err);
    }
}

//------------ State --------------------------------------------------------

/// The state of an SMTP connection
///
#[derive(Debug)]
enum State {
    Idle(Vec<u8>),
    InExchange(Box<Exchange + 'static>),
    Closing(Vec<u8>),
    Closed,
}

//------------ Exchange -----------------------------------------------------

/// A trait for an SMTP exchange.
///
/// An SMTP session is a sequence of exchanges which in turn are a sequence
/// of the client sending something and the server responding.
///
trait Exchange: Debug {
    fn interest(&self) -> Interest;
    fn on_readable(&mut self, transport: &mut TcpStream) -> Option<State> {
        let _ = transport;
        unreachable!();
    }
    fn on_writable(&mut self, transport: &mut TcpStream) -> Option<State> {
        let _ = transport;
        unreachable!();
    }
}


//------------ Responses ----------------------------------------------------

#[derive(Debug)]
struct Response {
    buf: Box<bytes::Buf + 'static>,
    next: State,
}

impl Response {
    fn new(data: &[u8], next: State) -> Response {
        Response {
            buf: Bytes::from_slice(data).buf(),
            next: next
        }
    }

    fn idle(data: &[u8]) -> Response {
        Response::new(data, State::Idle(Vec::new()))
    }

    fn closing(data: &[u8]) -> Response {
        Response::new(data, State::Closing(Vec::new()))
    }

    fn closed(data: &[u8]) -> Response {
        Response::new(data, State::Closed)
    }
}

impl Exchange for Response {
    fn interest(&self) -> Interest {
        Interest::Write
    }

    fn on_writable(&mut self, transport: &mut TcpStream) -> Option<State> {
        match transport.try_write_buf(&mut self.buf) {
            Ok(Some(..)) => {
                if self.buf.has_remaining() { None }
                else {
                    let next = mem::replace(&mut self.next, State::Closed);
                    Some(next)
                }
            },
            Ok(None) => { None },
            Err(e) => {
                debug!("SMTP connection write error: {:?}", e);
                Some(State::Closed)
            }
        }
    }
}


//------------ Helpers ------------------------------------------------------

fn has_crlf(buf: &[u8]) -> bool {
    for group in buf.split(|ch| *ch == b'\r') {
        if group.first() == Some(&&b'\n') { return true }
    }
    false
}

fn read_line<F>(transport: &mut TcpStream, buf: &mut Vec<u8>, f: F)
             -> Option<State>
            where F: Fn(&[u8]) -> State {
    // XXX For the moment we ignore trailing garbage. Not sur
    //     if that is smart. And too lazy to check the RFC.
    //
    match transport.try_read_buf(buf) {
        Ok(Some(0)) => Some(State::Closed),
        Ok(Some(_)) => {
            if has_crlf(buf) {
                Some(f(&buf))
            }
            else { None }
        },
        Ok(None) => { None }
        Err(e) => {
            debug!("SMTP connection read error: {:?}", e);
            Some(State::Closed)
        }
    }
}
