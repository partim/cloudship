//! An SMTP session.

use std::marker::PhantomData;
use std::rc::Rc;
use netmachines::sockets::Certificate;
use rotor::Notifier;
use ::smtp::syntax::{self, Command};
use super::buf::{RecvBuf, SendBuf};
use super::config::Config;
use super::protocol::{AncillaryHandler, DataHandler, Hesitant, Protocol,
                      SessionHandler, MailHandler, Undecided,
                      UndecidedReply};
use super::reply::{ReplyBuf, Reply};


//------------ Action -------------------------------------------------------

#[derive(Debug)]
pub enum Action {
    /// Read data.
    Read,

    /// Wait to be woken up
    Wait,

    /// Write all data then continue reading.
    ///
    /// If there is no data to write, continue reading right away. (This is
    /// true for all the other write variants as well.)
    Write,

    /// Collect more outbound data.
    ///
    /// If there is more data in the receive buffer, pretend that new data
    /// has arrived right away. Otherwise, send all data then continue
    /// reading.
    Collect,

    /// Write all data, then start a TLS handshake, then continue reading.
    StartTls,

    /// Write all data, then close the connection.
    Close
}


//------------ Session -------------------------------------------------------

pub struct Session<P: Protocol> {
    state: State<P>,
    config: Rc<Config>,
}

impl<P: Protocol> Session<P> {
    pub fn new(seed: <P::Session as SessionHandler<P>>::Seed,
               config: Rc<Config>, notifier: Notifier, send: &mut SendBuf)
               -> (Self, Action) {
        let (state, action) = Start::recv(seed, notifier)
                                    .process(send, &config);
        (Session { state: state, config: config }, action)
    }

    pub fn recv(mut self, recv: &mut RecvBuf, send: &mut SendBuf,
                is_secure: bool) -> (Self, Action) {
        let (state, action) = match self.state {
            State::Idle(idle) => idle.recv(recv, send, is_secure,
                                           &self.config),
            State::Wait(wait) => (State::Wait(wait), Action::Wait),
            State::Data(data) => data.recv(recv, send),
            State::Dead => Session::recv_dead(recv, send)
        };
        self.state = state;
        (self, action)
    }

    pub fn wakeup(mut self, send: &mut SendBuf, is_secure: bool)
                  -> (Self, Action) {
        if let State::Wait(wait) = self.state {
            let (state, action) = wait.wakeup(send, &self.config, is_secure);
            self.state = state;
            (self, action)
        }
        else {
            (self, Action::Read)
        }
    }

    pub fn confirm_tls<C: Certificate>(mut self, peer_cert: Option<C>)
                                       -> (Self, Action) {
        if let State::Idle(idle) = self.state {
            let (state, action) = idle.confirm_tls(peer_cert);
            self.state = state;
            (self, action)
        }
        else {
            // XXX Yeah, this is bad. There ought to be a better way.
            unreachable!()
        }
    }
}


impl<P: Protocol> Session<P> {
    fn recv_dead(recv: &mut RecvBuf, send: &mut SendBuf)
                 -> (State<P>, Action) {
        let res = recv.parse_command(|cmd| match cmd {
            Some(Command::Quit) => {
                send.reply(221, (2, 0, 0), b"Bye\r\n");
                Action::Close
            }
            Some(Command::Unrecognized) => {
                send.reply(500, (5, 5, 2),
                           b"Unrecognized command.\r\n");
                Action::Write
            }
            Some(Command::ParameterError) => {
                send.reply(501, (5, 5, 4),
                         b"Error in command parameters.\r\n");
                Action::Write
            }
            Some(_) => {
                send.reply(503, (5, 5, 1),
                           b"Please leave now\r\n");
                Action::Write
            },
            None => Action::Write,
        });
        match res {
            Ok(action) => (State::Dead, action),
            Err(()) => (State::Dead, Action::Close)
        }
    }
}


//------------ State ---------------------------------------------------------

enum State<P: Protocol> {
    /// A command is next.
    Idle(Idle<P>),

    /// Waiting for a final decision from the protocol.
    Wait(Wait<P>),

    /// Reading message data.
    Data(ReadData<P>),

    /// Waiting for a QUIT.
    Dead
}


impl<P: Protocol> From<Idle<P>> for State<P> {
    fn from(idle: Idle<P>) -> State<P> {
        State::Idle(idle)
    }
}

impl<P: Protocol> From<Wait<P>> for State<P> {
    fn from(wait: Wait<P>) -> State<P> {
        State::Wait(wait)
    }
}

impl<P: Protocol> From<ReadData<P>> for State<P> {
    fn from(data: ReadData<P>) -> State<P> {
        State::Data(data)
    }
}


//------------ Idle ----------------------------------------------------------

struct Idle<P: Protocol>(Level<P::Session, P::Mail>);

impl<P: Protocol> Idle<P> {
    fn early(session: P::Session) -> Self {
        Idle(Level::Early(session))
    }

    fn greeted(session: P::Session) -> Self {
        Idle(Level::Greeted(session))
    }

    fn mail(transaction: P::Mail) -> Self {
        Idle(Level::Mail(transaction))
    }
}


impl<P: Protocol> Idle<P> {
    fn recv(self, recv: &mut RecvBuf, send: &mut SendBuf, is_secure: bool,
            config: &Rc<Config>) -> (State<P>, Action) {
        let res = recv.parse_command(|cmd| match cmd {
            Some(Command::Helo(domain))
                => Helo::recv(self, domain).process(send, config),
            Some(Command::Ehlo(domain))
                => Ehlo::recv(self, domain).process(send, config, is_secure),
            Some(Command::Mail(path, params))
                => Mail::recv(self, path, params, send).process(),
            Some(Command::Rcpt(path, params))
                => Rcpt::recv(self, path, params, send).process(),
            Some(Command::Data)
                => Data::recv(self, send).process(send),
            Some(Command::Rset)
                => Rset::recv(self, send),
            Some(Command::Vrfy(what, params))
                => Vrfy::recv(self, what, params, send).process(),
            Some(Command::Expn(what, params))
                => Expn::recv(self, what, params, send).process(),
            Some(Command::Help(what))
                => Help::recv(self, what, send).process(),
            Some(Command::Noop) => {
                send.reply(250, (2,2,0), b"Ok\r\n");
                (self.into(), Action::Write)
            }
            Some(Command::Quit) => {
                send.reply(221, (2,0,0), b"Bye\r\n");
                (State::Dead, Action::Close)
            }
            Some(Command::StartTls) => {
                if is_secure {
                    send.reply(500, (5,5,2), b"Unrecognized command\r\n");
                    (self.into(), Action::Write)
                }
                else {
                    send.reply(220, (2,7,0), b"Ready to start TLS\r\n");
                    (self.into(), Action::StartTls)
                }
            }
            Some(Command::Auth{..}) | 
            Some(Command::Unrecognized) => {
                send.reply(500, (5,5,2), b"Unrecognized command.\r\n");
                (State::Idle(self), Action::Write)
            }
            Some(Command::ParameterError) => {
                send.reply(501, (5,5,4), b"Error in command parameters.\r\n");
                (State::Idle(self), Action::Write)
            }
            None => (State::Idle(self), Action::Read),
        });
        match res {
            Ok((state, action)) => (state, action),
            Err(()) => (State::Dead, Action::Close)
        }
    }

    fn confirm_tls<C: Certificate>(self, peer_cert: Option<C>)
                                   -> (State<P>, Action) {
        CheckTls::recv(self, peer_cert).process()
    }
}


//------------ Wait ----------------------------------------------------------

enum Wait<P: Protocol> {
    Start(<P::Session as SessionHandler<P>>::Start),
    Helo(<P::Session as SessionHandler<P>>::Hello),
    Ehlo(<P::Session as SessionHandler<P>>::Hello),
    Mail(<P::Session as SessionHandler<P>>::Mail),
    Rcpt(<P::Mail as MailHandler<P>>::Recipient),
    Data(<P::Mail as MailHandler<P>>::Data),
    Vrfy(WaitVrfy<P>),
    Expn(WaitExpn<P>),
    Help(WaitHelp<P>),
    CheckTls(<P::Session as SessionHandler<P>>::CheckTls),
    DataComplete(<P::Data as DataHandler<P>>::Complete),
}


impl<P: Protocol> Wait<P> {
    fn wakeup(self, send: &mut SendBuf, config: &Rc<Config>, is_secure: bool)
              -> (State<P>, Action) {
        match self {
            Wait::Start(defer) => Start::wakeup(defer).process(send, config),
            Wait::Helo(defer) => Helo::wakeup(defer).process(send, config),
            Wait::Ehlo(defer)
                => Ehlo::wakeup(defer).process(send, config, is_secure),
            Wait::Mail(defer) => Mail::wakeup(defer, send).process(),
            Wait::Rcpt(defer) => Rcpt::wakeup(defer, send).process(),
            Wait::Data(defer) => Data::wakeup(defer).process(send),
            Wait::Vrfy(defer) => Vrfy::wakeup(defer, send).process(),
            Wait::Expn(defer) => Expn::wakeup(defer, send).process(),
            Wait::Help(defer) => Help::wakeup(defer, send).process(),
            Wait::CheckTls(defer) => CheckTls::wakeup(defer).process(),
            Wait::DataComplete(defer)
                => DataComplete::wakeup(defer, send).process(),
        }
    }
}


//------------ ReadData ------------------------------------------------------

pub struct ReadData<P: Protocol>(P::Data);


impl<P: Protocol> ReadData<P> {
    fn new(data: P::Data) -> Self {
        ReadData(data)
    }

    fn recv(mut self, recv: &mut RecvBuf, send: &mut SendBuf)
            -> (State<P>, Action) {
        if let Some(idx) = recv.find_data_end() {
            self.0.chunk(&recv.as_slice()[0..idx]);
            recv.advance(idx + 5);
            DataComplete::recv(self.0, send).process()
        }
        else {
            let end = {
                let slice = recv.as_slice();
                if slice.len() >= 5 {
                    let end = slice.len() - 5;
                    self.0.chunk(&recv.as_slice()[0..end]);
                    end
                }
                else {
                    0
                }
            };
            recv.advance(end);
            (State::Data(self), Action::Read)
        }
    }
}


//------------ Level ---------------------------------------------------------

enum Level<S, M> {
    Early(S),
    Greeted(S),
    Mail(M)
}


//============ Helper Types for Command Processing ==========================
//
// These types exist to keep the three steps of processing a deferable
// command together in one place. As a bonus, the wrapped types help
// keeping the signatures of functions somewhat manageable. And finally,
// we cab use the doc comments of the types to include some notes on
// processing.


//------------ Start ---------------------------------------------------------

struct Start<P: Protocol>(Hesitant<Option<P::Session>,
                                   <P::Session as SessionHandler<P>>::Start>);

impl<P: Protocol> Start<P> {
    fn recv(seed: <P::Session as SessionHandler<P>>::Seed,
            notifier: Notifier) -> Self {
        Start(P::Session::start(seed, notifier))
    }

    fn wakeup(defer: <P::Session as SessionHandler<P>>::Start) -> Self {
        Start(defer.wakeup())
    }

    fn process(self, send: &mut SendBuf, config: &Rc<Config>)
               -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(Some(session)) => {
                scribble!(send, b"220 ", config.hostname(),
                          b" ESMTP ", config.systemname(), b"\r\n");
                (Idle::early(session).into(), Action::Write)
            }
            Hesitant::Final(None) => {
                // XXX We should probably be a little more specific. But
                //     let's see first if we'll actually have this case in
                //     practice at all.
                // XXX Maybe we should let the protocol write the response?
                scribble!(send, b"554 5.5.0 Connection refused.\r\n");
                (State::Dead, Action::Close)
            }
            Hesitant::Defer(defer) => {
                (State::Wait(Wait::Start(defer)), Action::Wait)
            }
        }
    }
}


//------------ Helo ----------------------------------------------------------

struct Helo<P: Protocol>(Hesitant<Option<P::Session>,
                                  <P::Session as SessionHandler<P>>::Hello>);

impl<P: Protocol> Helo<P> {
    fn recv(idle: Idle<P>, domain: syntax::Domain) -> Self {
        let session = match idle.0 {
            Level::Early(session) | Level::Greeted(session) => session,
            Level::Mail(transaction) => transaction.reset()
        };
        Helo(session.hello(syntax::MailboxDomain::Domain(domain)))
    }

    fn wakeup(defer: <P::Session as SessionHandler<P>>::Hello) -> Self {
        Helo(defer.wakeup())
    }

    fn process(self, send: &mut SendBuf, config: &Rc<Config>)
               -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(Some(session)) => {
                let mut reply = Reply::new(send, 250, None);
                scribble!(&mut reply, config.hostname(), b"\r\n");
                (Idle::greeted(session).into(), Action::Write)
            }
            Hesitant::Final(None) => {
                let mut reply = Reply::new(send, 550, None);
                scribble!(&mut reply, "Rejected for policy reasons\r\n");
                (State::Dead, Action::Close)
            }
            Hesitant::Defer(defer) => {
                (State::Wait(Wait::Helo(defer)), Action::Wait)
            }
        }
    }
}


//------------ Ehlo ----------------------------------------------------------

struct Ehlo<P: Protocol>(Hesitant<Option<P::Session>,
                                  <P::Session as SessionHandler<P>>::Hello>);

impl<P: Protocol> Ehlo<P> {
    fn recv(idle: Idle<P>, domain: syntax::MailboxDomain) -> Self {
        let session = match idle.0 {
            Level::Early(session) | Level::Greeted(session) => session,
            Level::Mail(transaction) => transaction.reset()
        };
        Ehlo(session.hello(domain))
    }

    fn wakeup(defer: <P::Session as SessionHandler<P>>::Hello) -> Self {
        Ehlo(defer.wakeup())
    }

    fn process(self, send: &mut SendBuf, config: &Rc<Config>, is_secure: bool)
               -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(Some(session)) => {
                let mut reply = Reply::new(send, 250, None);
                scribble!(&mut reply, config.hostname(),
                          b"\r\nEXPN\r\nHELP\r\n8BITMIME\r\nSIZE ",
                          config.message_size_limit(),
                          b"\r\nPIPELINING\r\nDSN\r\n\
                          ETRN\r\nENHANCEDSTATUSCODES\r\nSMTPUTF8\r\n");
                if !is_secure {
                    scribble!(&mut reply, b"STARTTLS\r\n");
                }
                (Idle::greeted(session).into(), Action::Write)
            }
            Hesitant::Final(None) => {
                let mut reply = Reply::new(send, 550, None);
                scribble!(&mut reply, "Rejected for policy reasons\r\n");
                (State::Dead, Action::Close)
            }
            Hesitant::Defer(defer) => {
                (State::Wait(Wait::Ehlo(defer)), Action::Wait)
            }
        }
    }
}


//------------ Mail ---------------------------------------------------------

struct Mail<P: Protocol>(Hesitant<Idle<P>,
                                  <P::Session as SessionHandler<P>>::Mail>);

impl<P: Protocol> Mail<P> {
    fn recv(idle: Idle<P>, path: syntax::ReversePath,
            params: syntax::MailParameters, send: &mut SendBuf) -> Self {
        match idle.0 {
            Level::Early(session) => {
                send.reply(503, (5,5,1), b"Please say 'Hello' first\r\n");
                Mail(Hesitant::Final(Idle::early(session)))
            }
            Level::Greeted(session) => {
                Mail(session.mail(path, params, ReplyBuf::new(send))
                            .map_final(Mail::translate))
            }
            Level::Mail(mail) => {
                send.reply(503, (5,5,1), b"Nested MAIL command\r\n");
                Mail(Hesitant::Final(Idle::mail(mail)))
            }
        }
    }

    fn wakeup(defer: <P::Session as SessionHandler<P>>::Mail,
              send: &mut SendBuf) -> Self {
        Mail(defer.wakeup(ReplyBuf::new(send)).map_final(Mail::translate))
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(idle) => {
                (State::Idle(idle), Action::Collect)
            }
            Hesitant::Defer(defer) => {
                (State::Wait(Wait::Mail(defer)), Action::Wait)
            }
        }
    }

    fn translate(res: Result<P::Mail, P::Session>) -> Idle<P> {
        match res {
            Ok(mail) => Idle::mail(mail),
            Err(session) => Idle::greeted(session)
        }
    }
}


//------------ Rcpt ----------------------------------------------------------

struct Rcpt<P>(Hesitant<Idle<P>,
                        <P::Mail as MailHandler<P>>::Recipient>)
            where P: Protocol;

impl<P: Protocol> Rcpt<P> {
    fn recv(idle: Idle<P>, path: syntax::RcptPath,
            params: syntax::RcptParameters, send: &mut SendBuf) -> Self {
        match idle.0 {
            Level::Early(session) => {
                send.reply(503, (5,5,1), b"Please say 'Hello' first\r\n");
                Rcpt(Hesitant::Final(Idle::early(session)))
            }
            Level::Greeted(session) => {
                send.reply(503, (5,5,1), b"Need MAIL command first\r\n");
                Rcpt(Hesitant::Final(Idle::greeted(session)))
            }
            Level::Mail(mail) => {
                Rcpt(mail.recipient(path, params, ReplyBuf::new(send))
                         .map_final(Rcpt::translate))
            }
        }
    }

    fn wakeup(defer: <P::Mail as MailHandler<P>>::Recipient,
              send: &mut SendBuf) -> Self {
        Rcpt(defer.wakeup(ReplyBuf::new(send)).map_final(Rcpt::translate))
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(idle) => (State::Idle(idle), Action::Collect),
            Hesitant::Defer(defer) => {
                (State::Wait(Wait::Rcpt(defer)), Action::Wait)
            }
        }
    }

    fn translate(res: Result<P::Mail, P::Session>) -> Idle<P> {
        match res {
            Ok(mail) => Idle::mail(mail),
            Err(session) => Idle::greeted(session)
        }
    }
}


//------------ Data ----------------------------------------------------------

struct Data<P>(Hesitant<Result<P::Data, Idle<P>>,
                        <P::Mail as MailHandler<P>>::Data>)
            where P: Protocol;

impl<P: Protocol> Data<P> {
    fn recv(idle: Idle<P>, send: &mut SendBuf) -> Self {
        match idle.0 {
            Level::Early(session) => {
                send.reply(503, (5,5,1), b"Please say 'Hello' first\r\n");
                Data(Hesitant::Final(Err(Idle::early(session))))
            }
            Level::Greeted(session) => {
                send.reply(503, (5,5,1), b"Need MAIL command first\r\n");
                Data(Hesitant::Final(Err(Idle::greeted(session))))
            }
            Level::Mail(mail) => {
                Data(mail.data().map_final(Data::translate))
            }
        }
    }

    fn wakeup(defer: <P::Mail as MailHandler<P>>::Data)
              -> Self {
        Data(defer.wakeup().map_final(Data::translate))
    }

    fn process(self, send: &mut SendBuf) -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(Ok(data)) => {
                let mut reply = Reply::new(send, 354, None);
                scribble!(&mut reply, b"Go ahead.\r\n");
                (State::Data(ReadData::new(data)), Action::Write)
            }
            Hesitant::Final(Err(idle)) => {
                send.reply(554, (5,5,0), b"Mail failed\r\n");
                (idle.into(), Action::Write)
            }
            Hesitant::Defer(defer) => {
                (Wait::Data(defer).into(), Action::Wait)
            }
        }
    }

    fn translate(res: Result<P::Data, P::Session>)
                 -> Result<P::Data, Idle<P>> {
        match res {
            Ok(data) => Ok(data),
            Err(session) => Err(Idle::greeted(session))
        }
    }
}


//------------ Rset ---------------------------------------------------------

struct Rset<P: Protocol>(PhantomData<P>);

impl<P: Protocol> Rset<P> {
    fn recv(idle: Idle<P>, send: &mut SendBuf) -> (State<P>, Action) {
        send.reply(250, (2,0,0), b"Ok\r\n");
        let idle = if let Level::Mail(mail) = idle.0 {
            Idle::greeted(mail.reset())
        }
        else { idle };
        (idle.into(), Action::Collect)
    }
}


//------------ Vrfy ---------------------------------------------------------

struct Vrfy<P>(Level<Hesitant<P::Session,
                              <P::Session as AncillaryHandler>::Verify>,
                     Hesitant<P::Mail,
                              <P::Mail as AncillaryHandler>::Verify>>)
            where P: Protocol;

impl<P: Protocol> Vrfy<P> {
    fn recv(idle: Idle<P>, what: syntax::Word, params: syntax::VrfyParameters,
            send: &mut SendBuf) -> Self {
        let reply = ReplyBuf::new(send);
        Vrfy(match idle.0 {
            Level::Early(session)
                => Level::Early(session.verify(what, params, reply)),
            Level::Greeted(session)
                => Level::Greeted(session.verify(what, params, reply)),
            Level::Mail(mail)
                => Level::Mail(mail.verify(what, params, reply))
        })
    }

    fn wakeup(defer: WaitVrfy<P>, send: &mut SendBuf) -> Self {
        let reply = ReplyBuf::new(send);
        Vrfy(match defer.0 {
            Level::Early(defer) => Level::Early(defer.wakeup(reply)),
            Level::Greeted(defer) => Level::Greeted(defer.wakeup(reply)),
            Level::Mail(defer) => Level::Mail(defer.wakeup(reply))
        })
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Level::Early(Hesitant::Final(session))
                => (Idle::early(session).into(), Action::Write),
            Level::Early(Hesitant::Defer(defer))
                => WaitVrfy(Level::Early(defer)).into(),
            Level::Greeted(Hesitant::Final(session))
                => (Idle::greeted(session).into(), Action::Write),
            Level::Greeted(Hesitant::Defer(defer))
                => WaitVrfy(Level::Greeted(defer)).into(),
            Level::Mail(Hesitant::Final(mail))
                => (Idle::mail(mail).into(), Action::Write),
            Level::Mail(Hesitant::Defer(defer))
                => WaitVrfy(Level::Mail(defer)).into(),
        }
    }
}


//------------ WaitVrfy ------------------------------------------------------

struct WaitVrfy<P: Protocol>(Level<<P::Session as AncillaryHandler>::Verify,
                                   <P::Mail as AncillaryHandler>::Verify>);

impl<P: Protocol> Into<(State<P>, Action)> for WaitVrfy<P> {
    fn into(self) -> (State<P>, Action) {
        (Wait::Vrfy(self).into(), Action::Wait)
    }
}


//------------ Expn ----------------------------------------------------------

struct Expn<P>(Level<Hesitant<P::Session,
                              <P::Session as AncillaryHandler>::Expand>,
                     Hesitant<P::Mail,
                              <P::Mail as AncillaryHandler>::Expand>>)
            where P: Protocol;

impl<P: Protocol> Expn<P> {
    fn recv(idle: Idle<P>, what: syntax::Word, params: syntax::ExpnParameters,
            send: &mut SendBuf) -> Self {
        let reply = ReplyBuf::new(send);
        Expn(match idle.0 {
            Level::Early(session)
                => Level::Early(session.expand(what, params, reply)),
            Level::Greeted(session)
                => Level::Greeted(session.expand(what, params, reply)),
            Level::Mail(mail)
                => Level::Mail(mail.expand(what, params, reply))
        })
    }

    fn wakeup(defer: WaitExpn<P>, send: &mut SendBuf) -> Self {
        let reply = ReplyBuf::new(send);
        Expn(match defer.0 {
            Level::Early(defer) => Level::Early(defer.wakeup(reply)),
            Level::Greeted(defer) => Level::Greeted(defer.wakeup(reply)),
            Level::Mail(defer) => Level::Mail(defer.wakeup(reply))
        })
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Level::Early(Hesitant::Final(session))
                => (Idle::early(session).into(), Action::Write),
            Level::Early(Hesitant::Defer(defer))
                => WaitExpn(Level::Early(defer)).into(),
            Level::Greeted(Hesitant::Final(session))
                => (Idle::greeted(session).into(), Action::Write),
            Level::Greeted(Hesitant::Defer(defer))
                => WaitExpn(Level::Greeted(defer)).into(),
            Level::Mail(Hesitant::Final(mail))
                => (Idle::mail(mail).into(), Action::Write),
            Level::Mail(Hesitant::Defer(defer))
                => WaitExpn(Level::Mail(defer)).into(),
        }
    }
}


//------------ WaitExpn ------------------------------------------------------

struct WaitExpn<P: Protocol>(Level<<P::Session as AncillaryHandler>::Expand,
                                   <P::Mail as AncillaryHandler>::Expand>);

impl<P: Protocol> Into<(State<P>, Action)> for WaitExpn<P> {
    fn into(self) -> (State<P>, Action) {
        (Wait::Expn(self).into(), Action::Wait)
    }
}


//------------ Help ---------------------------------------------------------

struct Help<P>(Level<Hesitant<P::Session,
                              <P::Session as AncillaryHandler>::Help>,
                     Hesitant<P::Mail, <P::Mail as AncillaryHandler>::Help>>)
            where P: Protocol;

const HELP_ACTION: Action = Action::Write;

impl<P: Protocol> Help<P> {
    fn recv(idle: Idle<P>, what: Option<syntax::Word>, send: &mut SendBuf)
            -> Self {
        let reply = ReplyBuf::new(send);
        Help(match idle.0 {
            Level::Early(session)
                => Level::Early(session.help(what, reply)),
            Level::Greeted(session)
                => Level::Greeted(session.help(what, reply)),
            Level::Mail(mail)
                => Level::Mail(mail.help(what, reply))
        })
    }

    fn wakeup(defer: WaitHelp<P>, send: &mut SendBuf) -> Self {
        let reply = ReplyBuf::new(send);
        Help(match defer.0 {
            Level::Early(defer) => Level::Early(defer.wakeup(reply)),
            Level::Greeted(defer) => Level::Greeted(defer.wakeup(reply)),
            Level::Mail(defer) => Level::Mail(defer.wakeup(reply))
        })
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Level::Early(Hesitant::Final(session))
                => (Idle::early(session).into(), HELP_ACTION),
            Level::Early(Hesitant::Defer(defer))
                => WaitHelp(Level::Early(defer)).into(),
            Level::Greeted(Hesitant::Final(session))
                => (Idle::greeted(session).into(), HELP_ACTION),
            Level::Greeted(Hesitant::Defer(defer))
                => WaitHelp(Level::Greeted(defer)).into(),
            Level::Mail(Hesitant::Final(mail))
                => (Idle::mail(mail).into(), HELP_ACTION),
            Level::Mail(Hesitant::Defer(defer))
                =>  WaitHelp(Level::Mail(defer)).into()
        }
    }
}


//------------ WaitHelp ------------------------------------------------------

struct WaitHelp<P: Protocol>(Level<<P::Session as AncillaryHandler>::Help,
                                   <P::Mail as AncillaryHandler>::Help>);

impl<P: Protocol> Into<(State<P>, Action)> for WaitHelp<P> {
    fn into(self) -> (State<P>, Action) {
        (Wait::Help(self).into(), Action::Wait)
    }
}


//------------ CheckTls ------------------------------------------------------

struct CheckTls<P>(Hesitant<Option<P::Session>,
                            <P::Session as SessionHandler<P>>::CheckTls>)
                where P: Protocol;

impl<P: Protocol> CheckTls<P> {
    fn recv<C: Certificate>(idle: Idle<P>, peer_cert: Option<C>) -> Self {
        let session = match idle.0 {
            Level::Early(session) | Level::Greeted(session) => session,
            Level::Mail(mail) => mail.reset()
        };
        CheckTls(session.check_tls(peer_cert))
    }

    fn wakeup(defer: <P::Session as SessionHandler<P>>::CheckTls) -> Self {
        CheckTls(defer.wakeup())
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(Some(session))
                => (Idle::early(session).into(), Action::Read),
            Hesitant::Final(None)
                => (State::Dead, Action::Read),
            Hesitant::Defer(defer)
                => (Wait::CheckTls(defer).into(), Action::Wait)
        }
    }
}


//------------ DataComplete --------------------------------------------------

struct DataComplete<P>(Hesitant<P::Session,
                                <P::Data as DataHandler<P>>::Complete>)
                    where P: Protocol;

impl<P: Protocol> DataComplete<P> {
    fn recv(data: P::Data, send: &mut SendBuf) -> Self {
        DataComplete(data.complete(ReplyBuf::new(send)))
    }

    fn wakeup(defer: <P::Data as DataHandler<P>>::Complete,
              send: &mut SendBuf) -> Self {
        DataComplete(defer.wakeup(ReplyBuf::new(send)))
    }

    fn process(self) -> (State<P>, Action) {
        match self.0 {
            Hesitant::Final(session)
                => (Idle::greeted(session).into(), Action::Collect),
            Hesitant::Defer(defer)
                => (Wait::DataComplete(defer).into(), Action::Wait)
        }
    }
}

