
use std::io;
use mio::{EventSet, PollOpt};
use rotor::Scope;
use ::net::tls::StartTlsStream;
use super::buf::{RecvBuf, SendBuf};
use super::protocol::{Context, Protocol};
use super::session::Session;


//------------ Connection ---------------------------------------------------

/// Wraps an SMTP server’s TCP connection.
///
/// This type owns the actual socket and performs the reading and writing
/// on it. For this purpose, it also owns a recv and send buffer which it
/// passes on to a `Session` which implements the business logic on top and
/// decides whether read or writing should be going on.
///
pub struct Connection<P: Protocol> {
    stream: StartTlsStream,
    session: Session<P>,
    action: Action,
    recv: RecvBuf,
    send: SendBuf,
}

impl<P: Protocol> Connection<P> {
    pub fn new(stream: StartTlsStream, scope: &mut Scope<P::Context>)
               -> io::Result<Self> {
        let recv = RecvBuf::new();
        let mut send = SendBuf::new();
        let notifier = scope.notifier();
        let (session, direction) = {
            let context: &P::Context = scope;
            Session::new(context, notifier, &mut send)
        };
        let action = Action::from_direction(direction, &recv);
        try!(scope.register(&stream, action.events(),
                            PollOpt::level() | PollOpt::oneshot()));
        Ok(Connection { stream: stream, session: session,
                        action: action, recv: recv, send: send })
    }

    fn reregister(self, scope: &mut Scope<P::Context>) -> Option<Self> {
        match self.action {
            Action::Wait => Some(self),
            _ => {
                match scope.reregister(&self.stream, self.action.events(),
                                       PollOpt::level() | PollOpt::oneshot()) {
                    Ok(()) => Some(self),
                    Err(e) => {
                        error!("SMTP connection reregister failed: {:?}", e);
                        None
                    }
                }
            }
        }
    }

    fn readable(mut self, scope: &mut Scope<P::Context>) -> Option<Self> {
        let res = match self.recv.try_read(&mut self.stream) {
            Ok(Some(0)) => { return None }
            Err(e) => {
                error!("SMTP connection read failed: {:?}", e);
                return None
            }
            Ok(None) => self,
            Ok(Some(_)) => {
                let (session, direction) =
                    self.session.receive(&mut self.recv, &mut self.send,
                                         self.stream.is_wrapped(), scope);
                Connection { session: session,
                             action: Action::from_direction(direction,
                                                            &self.recv),
                             .. self }
            }
        };
        res.reregister(scope)
    }

    fn writable(mut self, scope: &mut Scope<P::Context>) -> Option<Self> {
        match self.send.try_write(&mut self.stream) {
            Err(e) => {
                error!("SMTP connection write failed: {:?}", e);
                return None;
            }
            Ok(false) => {
                return self.reregister(scope);
            }
            Ok(true) => { }
        }

        match self.action {
            Action::Reply(AndThen::Receive) => {
                self.action = Action::Receive;
                self.reregister(scope)
            }
            Action::Reply(AndThen::Close) => None,
            Action::Reply(AndThen::StartTls) => self.starttls(scope),
            _ => { unreachable!() }
        }
    }

    fn starttls(self, scope: &mut Scope<P::Context>) -> Option<Self> {
        // XXX If we are wrapped already, we just go Receive. Not pretty
        // but hey.
        if self.stream.is_wrapped() {
            return Some(Connection { action: Action::Receive, .. self });
        }
        let stream = match self.stream.wrap_server(&scope.ssl_context()) {
            Ok(stream) => stream,
            Err(e) => {
                error!("SMTP connection: TLS handshake failed: {:?}",
                       e);
                return None
            }
        };
        let (session, direction) =
            self.session.checktls(stream.peer_certificate());
        let res = Connection { stream: stream, session: session,
                               action: Action::from_direction(direction,
                                                              &self.recv),
                               .. self };
        res.reregister(scope)
    }
}


// Interface towards Server
//
impl<P: Protocol> Connection<P> {
    pub fn ready(self, events: EventSet, scope: &mut Scope<P::Context>)
                 -> Option<Self> {
        if events.is_error() {
            error!("error event");
            return None;
        }

        // Process reading only if there isn't writing. Since we never
        // register both, that should be fine. But even if it isn't, we
        // register with level and will get the reading back once we are
        // ready for it.
        //
        if events.is_writable() {
            self.writable(scope)
        }
        else if events.is_readable() {
            self.readable(scope)
        }
        else {
            // XXX Can this really happen? Just reregister and keep going?
            self.reregister(scope)
        }
    }

    pub fn timeout(self, scope: &mut Scope<P::Context>) -> Option<Self> {
        let _ = scope;
        Some(self)
    }

    pub fn wakeup(mut self, scope: &mut Scope<P::Context>) -> Option<Self> {
        let (session, direction) = self.session.wakeup(&mut self.send,
                                                    self.stream.is_wrapped(), 
                                                    scope);
        let res = Connection { session: session,
                               action: Action::from_direction(direction,
                                                              &self.recv),
                               .. self };
        res.reregister(scope)
    }
}


//------------ Direction, Action, and Milestone -----------------------------
//
// Technically, just having Direction would be enough. However, by splitting
// this all up, all variants are always valid and we don’t need
// `unreachable!()` anywhere. Static checks through the type system for the
// win!
// 

/// Controls what the `Connection` should do.
///
/// This type is returned by the session to tell us what’s supposed to happen
/// next.
///
#[derive(Debug, PartialEq)]
pub enum Direction {
    /// Receive data and pass it to the session.
    Receive,

    /// Wait for further instructions. Do not involve the police.
    Wait,

    /// Write all data, then return to `Direction::Receive`.
    Reply,

    /// If the receive buffer is empty, proceed to `Direction::Reply`,
    /// otherwise, proceed to `Direction::Receive`.
    PipelineReply,

    /// Write all data, then move to `Direction::Closed`.
    Closing,

    /// Write all data, then start TLS handshake and report its result.
    StartTls,

}

#[derive(Debug, PartialEq)]
enum Action {
    /// Receive data
    Receive,

    /// Wait
    Wait,

    /// Send all available data, then do something
    Reply(AndThen)
}

#[derive(Debug, PartialEq)]
enum AndThen {
    /// Continue with reading data.
    Receive,

    /// Close the connection.
    Close,

    /// Start a TLS handshake.
    StartTls
}

// Derive an Action from a Direction.
//
// Because of `Direction::PipelineReply`, we need the receive buffer.
//
impl Action {
    fn from_direction(dir: Direction, recv: &RecvBuf) -> Self {
        match dir {
            Direction::Receive => Action::Receive,
            Direction::Wait => Action::Wait,
            Direction::Reply => Action::Reply(AndThen::Receive),
            Direction::PipelineReply => {
                if recv.is_empty() { Action::Reply(AndThen::Receive) }
                else { Action::Receive }
            }
            Direction::Closing => Action::Reply(AndThen::Close),
            Direction::StartTls => Action::Reply(AndThen::StartTls)
        }
    }

    fn events(&self) -> EventSet {
        match *self {
            Action::Receive => EventSet::readable(),
            Action::Wait => EventSet::none(),
            Action::Reply(_) => EventSet::writable(),
        }
    }
}

