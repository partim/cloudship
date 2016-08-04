//! Netmachines handlers.

use std::net::SocketAddr;
use std::rc::Rc;
use netmachines::{AcceptHandler, Next, TransportHandler};
use netmachines::sockets::HybridStream;
use rotor::Notifier;
use super::buf::{RecvBuf, SendBuf};
use super::config::Config;
use super::protocol::{Protocol, SessionHandler};
use super::session::{Action, Session};


//------------ Accept --------------------------------------------------------

pub struct Accept<P: Protocol> {
    config: Rc<Config>,
    protocol: P,
}

impl<P: Protocol> Accept<P> {
    pub fn new(config: Config, protocol: P) -> Self {
        Accept { config: Rc::new(config), protocol: protocol }
    }
}

impl<T: HybridStream, P: Protocol> AcceptHandler<T> for Accept<P> {
    type Output = Transport<P>;

    fn accept(&mut self, addr: &SocketAddr)
              -> Option<(<P::Session as SessionHandler<P>>::Seed,
                         Rc<Config>)> {
        self.protocol.accept(addr)
                     .map(|session| (session, self.config.clone()))
    }
}


//------------ Transport -----------------------------------------------------

pub struct Transport<P: Protocol> {
    session: Session<P>,
    plot: Plot,
    tls: Tls,
    recv: RecvBuf,
    send: SendBuf
}

#[derive(Debug, PartialEq)]
enum Tls {
    Clear,
    Handshake,
    Secure
}


impl<P: Protocol> Transport<P> {
    fn new(session: Session<P>, plot: Plot, recv: RecvBuf, send: SendBuf)
           -> Self {
        Transport { session: session, plot: plot, tls: Tls::Clear,
                    recv: recv, send: send }
    }

    fn next(self) -> Next<Self> {
        match self.plot {
            Plot::Read => Next::read(self),
            Plot::Wait => Next::wait(self),
            Plot::Write(_) => Next::write(self),
        }
    }

    fn next_plot(mut self, plot: Plot) -> Next<Self> {
        self.plot = plot;
        self.next()
    }

    /// Determines what happens next.
    ///
    /// This is called when writing ends (possibly without actually having
    /// written at all).
    fn and_then<T: HybridStream>(mut self, then: AndThen, sock: &mut T)
                                 -> Next<Self> {
        match then {
            AndThen::Read => self.recv(sock),
            AndThen::StartTls => {
                self.recv = RecvBuf::new();
                self.send = SendBuf::new();
                if let Err(err) = sock.accept_secure() {
                    error!("SMTP connection: TLS handshake failed: \
                           {:?}", err);
                    Next::remove()
                }
                else {
                    self.tls = Tls::Handshake;
                    self.next_plot(Plot::Read)
                } 
            }
            AndThen::Close => Next::remove()
        }
    }

    fn recv<T: HybridStream>(mut self, sock: &mut T) -> Next<Self> {
        let (session, action) = self.session.recv(&mut self.recv,
                                                  &mut self.send,
                                                  self.tls == Tls::Secure);
        self.session = session;
        match action {
            Action::Collect if !self.recv.is_empty() => self.recv(sock),
            _ => {
                let plot = Plot::from(action);
                match plot {
                    Plot::Read | Plot::Wait => self.next_plot(plot),
                    Plot::Write(then) => {
                        if self.send.is_empty() { self.and_then(then, sock) }
                        else { self.next_plot(Plot::Write(then)) }
                    }
                }
            }
        }
    }

    fn confirm_tls<T: HybridStream>(mut self, sock: &mut T) -> Next<Self> {
        self.tls = Tls::Secure;
        let (session, action) = self.session.confirm_tls(sock.get_peer_cert());
        self.session = session;
        let plot = Plot::from(action);
        match plot {
            Plot::Read => self.recv(sock),
            Plot::Wait => self.next_plot(plot),
            Plot::Write(then) => self.and_then(then, sock)
        }
    }
}


impl<T: HybridStream, P: Protocol> TransportHandler<T> for Transport<P> {
    type Seed = (<P::Session as SessionHandler<P>>::Seed, Rc<Config>);

    fn create(seed: Self::Seed, _sock: &mut T, notifier: Notifier)
              -> Next<Self> {
        let (seed, config) = seed;
        let recv = RecvBuf::new();
        let mut send = SendBuf::new();
        let (session, action) = Session::new(seed, config, notifier,
                                             &mut send);
        Transport::new(session, Plot::from(action), recv, send).next()
    }

    fn readable(mut self, sock: &mut T) -> Next<Self> {
        match self.recv.try_read(sock) {
            Ok(Some(0)) => Next::remove(),
            Err(e) => {
                error!("SMTP connection read failed: {:?}", e);
                Next::remove()
            }
            Ok(None) => self.next(),
            Ok(Some(_)) => {
                if let Tls::Handshake = self.tls { self.confirm_tls(sock) }
                else { self.recv(sock) }
            }
        }
    }

    fn writable(mut self, sock: &mut T) -> Next<Self> {
        match self.send.try_write(sock) {
            Err(e) => {
                error!("SMTP connection write failed: {:?}", e);
                Next::remove()
            }
            Ok(false) => self.next(),
            Ok(true) => {
                match self.plot {
                    Plot::Read => self.recv(sock),
                    Plot::Wait => self.next(),
                    Plot::Write(then) => self.and_then(then, sock)
                }
            }
        }
    }

    fn wakeup(mut self, sock: &mut T) -> Next<Self> {
        let (session, action) = self.session.wakeup(&mut self.send,
                                                    self.tls == Tls::Secure);
        self.session = session;
        let plot = Plot::from(action);
        match plot {
            Plot::Read => self.recv(sock),
            Plot::Wait => self.next_plot(plot),
            Plot::Write(then) => {
                if self.send.is_empty() { self.and_then(then, sock) }
                else { self.next_plot(plot) }
            }
        }
    }
}


//------------ Plot ----------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Plot {
    Read,
    Wait,
    Write(AndThen)
}

#[derive(Clone, Copy, Debug)]
enum AndThen {
    Read,
    StartTls,
    Close
}

impl Plot {
    fn from(action: Action) -> Self {
        match action {
            Action::Read => Plot::Read,
            Action::Wait => Plot::Wait,
            Action::Write => Plot::Write(AndThen::Read),
            Action::Collect => Plot::Write(AndThen::Read),
            Action::StartTls => Plot::Write(AndThen::StartTls),
            Action::Close => Plot::Write(AndThen::Close)
        }
    }
}

