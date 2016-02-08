
use nom::IResult;
use openssl::x509::X509;
use rotor::Notifier;
use ::util::scribe::Scribble;
use super::super::syntax::{self, Command};
use super::buf::{RecvBuf, SendBuf};
use super::connection::Direction;
use super::protocol::{Context, Hesitant, MailTransaction, Protocol};
use super::protocol::Hesitant::{Continue, Defer, Stop};
use super::reply::{ReplyBuf, Reply};


//------------ Session ------------------------------------------------------

pub enum Session<P: Protocol> {
    /// A command is next
    Idle(Idle<P>),

    /// Waiting for a final response from the protocol
    Wait(Wait<P>),

    /// Reading the message data
    Data(Data<P>),

    /// Waiting for a QUIT
    Dead
}

impl<P: Protocol> Session<P> {
    /// Creates a new session.
    ///
    pub fn new(context: &P::Context, notifier: Notifier, send: &mut SendBuf)
               -> (Self, Direction) {
        match P::create(context, notifier) {
            Some(proto) => {
                scribble!(send, b"220 ", context.hostname(),
                          b" ESMTP ", context.systemname(), b"\r\n");
                (Idle::session(proto, State::Early), Direction::Reply)
            }
            None => {
                // XXX We should probably be a little more specific. But
                //     let's see first if we'll actually have this case in
                //     practice at all.
                // XXX Maybe we should let the protocol write the response?
                scribble!(send, b"554 5.5.0 Connection refused.\r\n");
                (Session::Dead, Direction::Closing)
            }
        }
    }

    /// The connection has received some data.
    ///
    pub fn receive(self, recv: &mut RecvBuf, send: &mut SendBuf,
                   tls: bool, context: &P::Context)
                   -> (Session<P>, Direction) {
        match self {
            Session::Idle(idle) => idle.receive(recv, send, tls, context),
            Session::Wait(wait) => (Session::Wait(wait), Direction::Wait),
            Session::Data(data) => data.receive(recv, send),
            Session::Dead => Session::receive_dead(recv, send),
        }
    }

    /// The connection was woken up.
    ///
    pub fn wakeup(self, send: &mut SendBuf, tls: bool, context: &P::Context)
                  -> (Session<P>, Direction) {
        match self {
            Session::Wait(session) => session.wakeup(send, tls, context),
            _ => (self, Direction::Receive),
        }
    }

    pub fn checktls(self, peer_cert: Option<X509>) -> (Session<P>, Direction) {
        match self {
            Session::Idle(idle) => idle.checktls(peer_cert),
            Session::Dead => (Session::Dead, Direction::Receive),
            // Rather blow up than accepting an unacceptable TLS connection
            _ => unreachable!()
        }
    }
}


impl<P: Protocol> Session<P> {
    fn receive_dead(recv: &mut RecvBuf, send: &mut SendBuf)
                    -> (Self, Direction) {
        let len = recv.len();
        let (advance, res) = match Command::parse(recv.as_slice()) {
            IResult::Done(rest, cmd) => {
                match cmd {
                    Command::Quit => {
                        send.reply(221, (2, 0, 0), b"Bye\r\n");
                    }
                    Command::Unrecognized => {
                        send.reply(500, (5, 5, 2),
                                   b"Unrecognized command.\r\n");
                    }
                    Command::ParameterError => {
                        send.reply(501, (5, 5, 4),
                                 b"Error in command parameters.\r\n");
                    }
                    _ => {
                        send.reply(503, (5, 5, 1),
                                   b"Please leave now\r\n");
                    }
                }
                (len - rest.len(), (Session::Dead, Direction::Reply))
            }
            IResult::Error(e) => {
                error!("SMTP server: parse error: {:?}", e);
                (0, (Session::Dead, Direction::Closing))
            }
            IResult::Incomplete(..) => {
                (0, (Session::Dead, Direction::Receive))
            }
        };
        recv.advance(advance);
        res
    }
}


// Processing for deferable commands
impl<P: Protocol> Session<P> {

    fn hello(proto: Hesitant<P>, send: &mut SendBuf, context: &P::Context)
             -> (Self, Direction) {
        match proto {
            Continue(proto) => {
                let mut reply = Reply::new(send, 250, None);
                scribble!(&mut reply, context.hostname(), b"\r\n");
                (Idle::session(proto, State::Session), Direction::Reply)
            }
            Stop => {
                let mut reply = Reply::new(send, 550, None);
                scribble!(&mut reply, "Rejected for policy reasons\r\n");
                (Session::Dead, Direction::Closing)
            }
            Defer(proto) => {
                (Wait::session(proto, Next::Hello), Direction::Wait)
            }
        }
    }

    fn ehello(proto: Hesitant<P>, send: &mut SendBuf, tls: bool,
              context: &P::Context) -> (Self, Direction) {
        match proto {
            Continue(proto) => {
                let mut reply = Reply::new(send, 250, None);
                scribble!(&mut reply, context.hostname(),
                          b"\r\nEXPN\r\nHELP\r\n8BITMIME\r\nSIZE ",
                          context.message_size_limit(),
                          b"\r\nPIPELINING\r\nDSN\r\n\
                          ETRN\r\nENHANCEDSTATUSCODES\r\nSMTPUTF8\r\n");
                if !tls {
                    scribble!(&mut reply, b"STARTTLS\r\n");
                }
                (Idle::session(proto, State::Session), Direction::Reply)
            }
            Stop => {
                let mut reply = Reply::new(send, 550, None);
                scribble!(&mut reply, "Rejected for policy reasons\r\n");
                (Session::Dead, Direction::Closing)
            }
            Defer(proto) => {
                (Wait::session(proto, Next::EHello),
                 Direction::Wait)
            }
        }
    }

    fn mail(proto: P, mail: Hesitant<P::Mail>) -> (Self, Direction) {
        match mail {
            Continue(mail) => (Idle::session(proto, State::Mail(mail)),
                               Direction::PipelineReply),
            Stop => (Idle::session(proto, State::Session),
                     Direction::PipelineReply),
            Defer(mail) => (Wait::session(proto, Next::Mail(mail)),
                            Direction::Wait)
        }
    }

    fn recipient(proto: P, mail: Hesitant<P::Mail>) -> (Self, Direction) {
        match mail {
            Continue(mail) => (Idle::session(proto, State::Recipients(mail)),
                               Direction::PipelineReply),
            Stop => (Idle::session(proto, State::Session),
                     Direction::PipelineReply),
            Defer(mail) => (Wait::session(proto, Next::Recipient(mail)),
                            Direction::Wait)
        }
    }

    fn data(proto: P, mail: Hesitant<P::Mail>, send: &mut SendBuf)
            -> (Self, Direction) {
        match mail {
            Continue(mail) => {
                let mut reply = Reply::new(send, 354, None);
                scribble!(&mut reply, b"Go ahead.\r\n");
                (Data::session(proto, mail), Direction::Reply)
            }
            Stop => {
                send.reply(554, (5,5,0), b"Transaction failed\r\n");
                (Idle::session(proto, State::Session), Direction::Reply)
            }
            Defer(mail) => {
                (Wait::session(proto, Next::Data(mail)), Direction::Wait)
            }
        }
    }

    fn reset(proto: P, mail: Hesitant<P::Mail>, send: &mut SendBuf)
             -> (Self, Direction) {
        match mail {
            Continue(..) | Stop => {
                send.reply(250, (2,0,0), b"Ok\r\n");
                (Idle::session(proto, State::Session),
                 Direction::PipelineReply)
            }
            Defer(mail) => {
                (Wait::session(proto, Next::Reset(mail)), Direction::Wait)
            }
        }
    }

    fn verify(proto: Hesitant<P>, state: State<P>) -> (Self, Direction) {
        match proto {
            Continue(proto) =>
                (Idle::session(proto, state), Direction::Reply),
            Defer(proto) =>
                (Wait::session(proto, Next::Verify(state)), Direction::Wait),
            Stop => (Session::Dead, Direction::Reply)
        }
    }

    fn expand(proto: Hesitant<P>, state: State<P>) -> (Self, Direction) {
        match proto {
            Continue(proto) =>
                (Idle::session(proto, state), Direction::Reply),
            Defer(proto) =>
                (Wait::session(proto, Next::Expand(state)), Direction::Wait),
            Stop => (Session::Dead, Direction::Reply)
        }
    }

    fn help(proto: Hesitant<P>, state: State<P>) -> (Self, Direction) {
        match proto {
            Continue(proto) =>
                (Idle::session(proto, state), Direction::Reply),
            Defer(proto) =>
                (Wait::session(proto, Next::Help(state)), Direction::Wait),
            Stop => (Session::Dead, Direction::Reply)
        }
    }

    fn final_checktls(proto: Hesitant<P>) -> (Self, Direction) {
        match proto {
            Continue(proto) =>
                (Idle::session(proto, State::Early), Direction::Receive),
            Defer(proto) =>
                (Wait::session(proto, Next::StartTls), Direction::Wait),
            Stop => (Session::Dead, Direction::Receive)
        }
    }

    fn complete(proto: P, mail: Hesitant<P::Mail>) -> (Self, Direction) {
        match mail {
            Continue(..) | Stop =>
                (Idle::session(proto, State::Session),
                 Direction::PipelineReply),
            Defer(mail) =>
                (Wait::session(proto, Next::Complete(mail)), Direction::Wait)
        }
    }
}


//------------ Idle ---------------------------------------------------------

pub struct Idle<P: Protocol> {
    proto: P,
    state: State<P>,
}

pub enum State<P: Protocol> {
    /// No EHLO/HELO has been received yet. Waiting for the next command.
    Early,

    /// A EHLO/HELO has been received. Waiting for the next command.
    Session,

    /// A mail transaction is being prepared.
    Mail(P::Mail),

    /// A mail transaction has at least one recipient.
    Recipients(P::Mail),
}


impl<P: Protocol> Idle<P> {
    fn session(proto: P, state: State<P>) -> Session<P> {
        Session::Idle(Idle { proto: proto, state: state })
    }

    /// Parses a single command and passes it on for processing.
    ///
    /// Returns the new session and what to do next. `Direction::Reply`
    /// means to send a reply, `Direction::PipelineReply` means to send a
    /// reply if there is no more data, `Direction::Receive` means we need
    /// more data to decide.
    ///
    fn receive(self, recv: &mut RecvBuf, send: &mut SendBuf, tls: bool,
               context: &P::Context) -> (Session<P>, Direction) {
        let len = recv.len();
        let (advance, res) = match Command::parse(recv.as_slice()) {
            IResult::Done(rest, cmd) => {
                (len - rest.len(), self.command(cmd, send, tls, context))
            }
            IResult::Error(e) => {
                error!("SMTP server: parse error: {:?}", e);
                (0, (Session::Dead, Direction::Closing))
            }
            IResult::Incomplete(..) => {
                (0, (Session::Idle(self), Direction::Receive))
            }
        };
        recv.advance(advance);
        res
    }

    fn command(self, cmd: Command, send: &mut SendBuf, tls: bool,
               context: &P::Context) -> (Session<P>, Direction) {
        match cmd {
            Command::Helo(domain) => self.hello(domain, send, context),
            Command::Ehlo(domain) => self.ehello(domain, send, tls, context),
            Command::Mail(path, params) => self.mail(path, params, send),
            Command::Rcpt(path, params) => self.recipient(path, params, send),
            Command::Data => self.data(send),
            Command::Rset => self.reset(send),
            Command::Vrfy(what, params) => self.verify(what, params, send),
            Command::Expn(what, params) => self.expand(what, params, send),
            Command::Help(what) => self.help(what, send),
            Command::Noop => self.noop(send),
            Command::Quit => self.quit(send),
            Command::StartTls => self.starttls(send, tls),
            Command::Auth{mechanism, initial} => self.auth(mechanism,
                                                           initial, send),
            Command::Unrecognized => {
                send.reply(500, (5,5,2), b"Unrecognized command.\r\n");
                (Session::Idle(self), Direction::Reply)
            }
            Command::ParameterError => {
                send.reply(501, (5,5,4), b"Error in command parameters.\r\n");
                (Session::Idle(self), Direction::Reply)
            }
        }
    }

    fn checktls(self, peer_certificate: Option<X509>)
                -> (Session<P>, Direction) {
        Session::final_checktls(self.proto.starttls(peer_certificate))
    }
}

// Individual commands
//
impl<P: Protocol> Idle<P> {
    fn hello(self, domain: syntax::Domain, send: &mut SendBuf,
             context: &P::Context) -> (Session<P>, Direction) {
        Session::hello(self.proto.hello(syntax::MailboxDomain::Domain(domain)),
                       send, context)
    }

    fn ehello(self, domain: syntax::MailboxDomain, send: &mut SendBuf,
              tls: bool, context: &P::Context) -> (Session<P>, Direction) {
        Session::ehello(self.proto.hello(domain), send, tls, context)
    }

    fn mail(self, path: syntax::ReversePath, params: syntax::MailParameters,
            send: &mut SendBuf) -> (Session<P>, Direction) {
        match self.state {
            State::Early => {
                send.reply(503, (5,5,1), b"Please say 'Hello' first\r\n");
                (Session::Idle(self), Direction::PipelineReply)
            }
            State::Session => {
                let mail = self.proto.mail();
                Session::mail(self.proto, mail.mail(path, params,
                                                    ReplyBuf::new(send)))
            }
            State::Mail(..) | State::Recipients(..) => {
                send.reply(503, (5,5,1), b"Nested MAIL command\r\n");
                (Session::Idle(self), Direction::PipelineReply)
            }
        }
    }

    fn recipient(self, path: syntax::RcptPath, params: syntax::RcptParameters,
                 send: &mut SendBuf) -> (Session<P>, Direction) {
        match self.state {
            State::Mail(mail) | State::Recipients(mail) => {
                Session::recipient(self.proto,
                                   mail.recipient(path, params,
                                                  ReplyBuf::new(send)))
            }
            _ => {
                send.reply(503, (5,5,1), b"Need MAIL command first\r\n");
                (Session::Idle(self), Direction::PipelineReply)
            }
        }
    }

    fn data(self, send: &mut SendBuf) -> (Session<P>, Direction) {
        match self.state {
            State::Recipients(mail) => {
                Session::data(self.proto, mail.data(), send)
            }
            State::Mail(..) => {
                send.reply(503, (5,5,1), b"Need RCPT command first\r\n");
                (Session::Idle(self), Direction::Reply)
            }
            _ => {
                send.reply(503, (5,5,1), b"Need MAIL command first\r\n");
                (Session::Idle(self), Direction::Reply)
            }
        }
    }

    fn reset(self, send: &mut SendBuf) -> (Session<P>, Direction) {
        match self.state {
            State::Mail(mail) | State::Recipients(mail) => {
                Session::reset(self.proto, mail.reset(), send)
            }
            _ => {
                send.reply(250, (2,0,0), b"Ok\r\n");
                (Session::Idle(self), Direction::PipelineReply)
            }
        }
    }

    fn verify(self, what: syntax::Word, params: syntax::VrfyParameters,
              send: &mut SendBuf) -> (Session<P>, Direction) {
        Session::verify(self.proto.verify(what, params, ReplyBuf::new(send)),
                        self.state)
    }

    fn expand(self, what: syntax::Word, params: syntax::ExpnParameters,
              send: &mut SendBuf) -> (Session<P>, Direction) {
        Session::expand(self.proto.expand(what, params, ReplyBuf::new(send)),
                        self.state)
    }

    fn help(self, what: Option<syntax::Word>, send: &mut SendBuf)
            -> (Session<P>, Direction) {
        Session::help(self.proto.help(what, ReplyBuf::new(send)), self.state)
    }

    fn noop(self, send: &mut SendBuf) -> (Session<P>, Direction) {
        send.reply(250, (2,2,0), b"Ok\r\n");
        (Session::Idle(self), Direction::Reply)
    }

    fn quit(self, send: &mut SendBuf) -> (Session<P>, Direction) {
        send.reply(221, (2,0,0), b"Bye\r\n");
        (Session::Dead, Direction::Closing)
    }

    fn starttls(self, send: &mut SendBuf, tls: bool)
                -> (Session<P>, Direction) {
        if tls {
            send.reply(500, (5,5,2), b"Unrecognized command\r\n");
            (Session::Idle(self), Direction::Reply)
        }
        else {
            send.reply(220, (2,7,0), b"Ready to start TLS\r\n");
            (Session::Idle(self), Direction::StartTls)
        }
    }

    fn auth(self, mechanism: &[u8], initial: Option<&[u8]>,
            send: &mut SendBuf) -> (Session<P>, Direction) {
        let _ = (mechanism, initial);
        send.reply(500, (5,5,2), b"Unrecognized command\r\n");
        (Session::Idle(self), Direction::Reply)
    }
}


//------------ WaitSession --------------------------------------------------

pub struct Wait<P: Protocol> {
    proto: P,
    next: Next<P>
}


pub enum Next<P: Protocol> {
    Hello,
    EHello,
    StartTls,
    Verify(State<P>),
    Expand(State<P>),
    Help(State<P>),
    Mail(P::Mail),
    Recipient(P::Mail),
    Data(P::Mail),
    Complete(P::Mail),
    Reset(P::Mail),
}


impl<P: Protocol> Wait<P> {
    fn session(proto: P, next: Next<P>) -> Session<P> {
        Session::Wait(Wait { proto: proto, next: next })
    }

    fn wakeup(self, send: &mut SendBuf, tls: bool, context: &P::Context)
              -> (Session<P>, Direction) {
        match self.next {
            Next::Hello =>
                Session::hello(self.proto.continue_hello(), send, context),
            Next::EHello =>
                Session::ehello(self.proto.continue_hello(), send, tls,
                                context),
            Next::Mail(mail) => 
                Session::mail(self.proto,
                              mail.continue_mail(ReplyBuf::new(send))),
            Next::Recipient(mail) =>
                Session::recipient(self.proto,
                                   mail.continue_recipient(
                                       ReplyBuf::new(send))),
            Next::Data(mail) =>
                Session::data(self.proto, mail.continue_data(), send),
            Next::Complete(mail) =>
                Session::complete(self.proto, mail.continue_complete(
                                                    ReplyBuf::new(send))),
            Next::Reset(mail) =>
                Session::reset(self.proto, mail.continue_reset(), send),
            Next::Verify(state) =>
                Session::verify(self.proto.continue_verify(
                                                       ReplyBuf::new(send)),
                                state),
            Next::Expand(state) =>
                Session::expand(self.proto.continue_expand(
                                                       ReplyBuf::new(send)),
                                state),
            Next::Help(state) =>
                Session::help(self.proto.continue_help(ReplyBuf::new(send)),
                              state),
            Next::StartTls =>
                Session::final_checktls(self.proto.continue_starttls()),
        }
    }
}


//------------ Data ---------------------------------------------------------

pub struct Data<P: Protocol> {
    proto: P,
    mail: P::Mail,
}

impl<P: Protocol> Data<P> {
    fn session(proto: P, mail: P::Mail) -> Session<P> {
        Session::Data(Data { proto: proto, mail: mail })
    }

    fn receive(mut self, recv: &mut RecvBuf, send: &mut SendBuf)
               -> (Session<P>, Direction) {
        if let Some(idx) = recv.find_data_end() {
            self.mail.chunk(&recv.as_slice()[0..idx]);
            recv.advance(idx + 5);
            Session::complete(self.proto,
                              self.mail.complete(ReplyBuf::new(send)))
        }
        else {
            let end = {
                let slice = recv.as_slice();
                if slice.len() >= 5 {
                    let end = slice.len() - 5;
                    self.mail.chunk(&recv.as_slice()[0..end]);
                    end
                }
                else {
                    0
                }
            };
            recv.advance(end);
            (Session::Data(self), Direction::Receive)
        }
    }
}

