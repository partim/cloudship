
use std::io;
use std::net::SocketAddr;
use mio::{EventSet, PollOpt};
use rotor::{GenericScope, Machine, Response, Scope};
use rotor::void::Void;
use ::net::tls::{StartTlsListener, StartTlsStream};
use super::protocol::Protocol;
use super::connection::Connection;

/// The SMTP server.
///
/// Create a server either by passing a `StartTlsListener` instance and a
/// `rotor::Scope``to `Server::new()` or let the server create the listener
/// by itself using the convenience function `bind()`. Then add the result
/// to a rotor loop.
///
/// This type provides the rotor machine for both the TCP listening and
/// connected sockets of an SMTP server. For the connected sockets, it
/// dispatches events to a `Connection` object. For the listening sockets,
/// it accepts new connections and creates such objects.
///
pub enum Server<P: Protocol> {
    Listener(StartTlsListener),
    Connection(Connection<P>)
}

impl<P: Protocol> Server<P> {
    /// Creates a new server using *lsnr* and registers it with *scope*.
    ///
    pub fn new<S: GenericScope>(lsnr: StartTlsListener, scope: &mut S)
                            -> io::Result<Self> {
        try!(scope.register(&lsnr, EventSet::readable(), PollOpt::edge()));
        Ok(Server::Listener(lsnr))
    }

    /// Creates a new server listening on *addr* and registers it with *scope*.
    ///
    pub fn bind<S: GenericScope>(addr: &SocketAddr, scope: &mut S)
                             -> io::Result<Self> {
        let lsnr = try!(StartTlsListener::bind(addr));
        Self::new(lsnr, scope)
    }
}

impl<P: Protocol> Machine for Server<P> {
    type Context = P::Context;
    type Seed = StartTlsStream;

    fn create(sock: StartTlsStream, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        match Connection::new(sock, scope) {
            Ok(conn) => Response::ok(Server::Connection(conn)),
            Err(err) => Response::error(Box::new(err))
        }
    }

    fn ready(self, events: EventSet, scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        match self {
            Server::Listener(lsnr) => {
                match lsnr.accept() {
                    Ok(Some((sock,_))) => {
                        Response::spawn(Server::Listener(lsnr), sock)
                    }
                    Ok(None) => Response::ok(Server::Listener(lsnr)),
                    Err(_) => Response::ok(Server::Listener(lsnr)),
                }
            }
            Server::Connection(conn) => {
                conn.ready(events, scope)
                    .map_or(Response::done(),
                            |conn| Response::ok(Server::Connection(conn)))
            }
        }
    }

    fn spawned(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        let _ = scope;
        match self {
            Server::Listener(lsnr) => {
                match lsnr.accept() {
                    Ok(Some((sock,_))) => {
                        Response::spawn(Server::Listener(lsnr), sock)
                    }
                    Ok(None) => Response::ok(Server::Listener(lsnr)),
                    Err(_) => Response::ok(Server::Listener(lsnr))
                }
            }
            Server::Connection(_) => unreachable!(),
        }
    }

    fn timeout(self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        match self {
            Server::Listener(_) => unreachable!(),
            Server::Connection(conn) => {
                conn.timeout(scope)
                    .map_or(Response::done(),
                            |conn| Response::ok(Server::Connection(conn)))
            }
        }
    }

    fn wakeup(self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        match self {
            Server::Listener(_) => unreachable!(),
            Server::Connection(conn) => {
                conn.wakeup(scope)
                    .map_or(Response::done(),
                            |conn| Response::ok(Server::Connection(conn)))
            }
        }
    }
}
