use std::io::Write;
use std::mem;
use nom::IResult;
use super::connection::{Direction, RecvBuf, SendBuf};
use super::handler::{SessionHandler, MailTransaction, MailData};
use super::super::protocol::{Command, CommandError, Domain, ExpnParameters, 
                             MailboxDomain, MailParameters, RcptPath,
                             RcptParameters, ReversePath, VrfyParameters,
                             Word,};
use ::util::scribe::{Scribe, Scribble};

//------------ Session ------------------------------------------------------

// An SMTP session on top of an SMTP connection
//
pub struct Session<H: SessionHandler> {
    state: State<H>,
    handler: H,
}

impl<H: SessionHandler> Session<H> {
    pub fn new(handler: H) -> Self {
        Session {
            state: State::Early,
            handler: handler,
        }
    }

    pub fn process(&mut self, recv: &mut RecvBuf, send: &mut SendBuf)
                   -> Direction {
        if self.state.is_data() {
            self.process_data(recv, send)
        }
        else {
            self.process_command(recv, send)
        }
    }

    fn process_data(&mut self, recv: &mut RecvBuf, send: &mut SendBuf)
                    -> Direction {
        let state = mem::replace(&mut self.state, State::Early);
        let (state, direction) = match state {
            State::MailData(mut data) => {
                if let Some(idx) = recv.find_data_end() {
                    // XXX What do we do when write fails?
                    let _ = data.write(&recv.as_slice()[0..idx]);
                    recv.advance(idx + 5);
                    data.done(ProtoReply::new(send));
                    self.state = State::Session;
                    if recv.is_empty() {
                        (State::Session, Direction::Reply)
                    }
                    else {
                        (State::Session, Direction::Receive)
                    }
                }
                else {
                    // XXX What do we do when write fails?
                    let _ = data.write(recv.as_slice());
                    (State::MailData(data), Direction::Receive)
                }
            }
            _ => unreachable!()
        };
        self.state = state;
        direction
    }

    fn process_command(&mut self, recv: &mut RecvBuf, send: &mut SendBuf)
                       -> Direction {
        let len = recv.len();
        let (advance, dir) = match Command::parse(recv.as_slice()) {
            IResult::Done(rest, Ok(cmd)) => {
                (len - rest.len(), self.command(cmd, send, rest.len() == len))
            }
            IResult::Done(rest, Err(e)) => {
                Reply::error(send, e);
                (len - rest.len(), Direction::Reply)
            }
            IResult::Error(..) => {
                (0, Direction::Closed)
            }
            IResult::Incomplete(..) => (0, Direction::Receive)
        };
        recv.advance(advance);
        dir
    }


    //--- Command Processing

    /// Process a command.
    ///
    /// If `last` is `true`, this is the last command in a pipelined
    /// sequence.
    ///
    /// Returns the `Direction` to continue with.
    ///
    pub fn command(&mut self, cmd: Command, send: &mut SendBuf, last: bool)
                   -> Direction {
        debug!("Got command {:?}", cmd);
        let pipeline = cmd.allow_pipeline();
        let mut quit = false;
        match cmd {
            Command::Ehlo(domain) => self.ehello(domain, send),
            Command::Helo(domain) => self.hello(domain, send),
            Command::Mail(path, params) => self.mail(path, params, send),
            Command::Rcpt(path, params) => self.recipient(path, params, send),
            Command::Data => self.data(send),
            Command::Rset => self.reset(send),
            Command::Vrfy(whom, params) => self.verify(whom, params, send),
            Command::Expn(whom, params) => self.expand(whom, params, send),
            Command::Help(what) => self.help(what, send),
            Command::Noop => self.noop(send),
            Command::Quit => { self.quit(send); quit = true }
            Command::StartTls => self.starttls(send),
            Command::Auth{mechanism, initial} => self.auth(mechanism, initial,
                                                           send),
        }
        if quit { Direction::Closing }
        else if last || !pipeline { Direction::Reply }
        else { Direction::Receive }
    }

    // > S: 250
    // > E: 504 (a conforming implementation could return this code only
    // > in fairly obscure cases), 550, 502 (permitted only with an old-
    // > style server that does not support EHLO)
    fn hello(&mut self, domain: Domain, send: &mut SendBuf) {
        self.handler.hello(MailboxDomain::Domain(domain));
        let mut reply = Reply::new(send, 205, None);
        self.handler.scribble_hostname(&mut reply);
        scribble!(&mut reply, b"\r\n");
        self.state = State::Session;
    }

    // > S: 250
    // > E: 504 (a conforming implementation could return this code only
    // > in fairly obscure cases), 550, 502 (permitted only with an old-
    // > style server that does not support EHLO)
    fn ehello(&mut self, domain: MailboxDomain, send: &mut SendBuf) {
        self.handler.hello(domain);
        let mut reply = Reply::new(send, 205, None);
        self.handler.scribble_hostname(&mut reply);
        scribble!(&mut reply,
                  b"\r\nEXPN\r\nHELP\r\n8BITMIME\r\nSIZE ",
                  self.handler.message_size_limit(),
                  b"\r\nPIPELINING\r\nDSN\r\n\
                  ETRN\r\nENHANCEDSTATUSCODES\r\nSTARTTLS\r\nAUTH\r\n\
                  SMTPUTF8\r\n");
        self.state = State::Session;
    }

    // > S: 250
    // > E: 552, 451, 452, 550, 553, 503, 455, 555
    fn mail(&mut self, path: ReversePath, params: MailParameters,
            send: &mut SendBuf) {
        match self.state {
            State::Session => {
                match self.handler.mail(path, params, ProtoReply::new(send)) {
                    None => {},
                    Some(mail) => {
                        self.state = State::MailRcpt(mail)
                    }
                }
            }
            State::Early => {
                Reply::reply(send, 503, (5,5,1),
                             b"Please say 'Hello' first\r\n");
            }
            State::Closing => {
                Reply::reply(send, 503, (5,5,1), b"Please leave now\r\n");
            }
            _ => {
                Reply::reply(send, 503, (5,5,1), b"Nested MAIL command\r\n");
            }
        }
    }

    // > S: 250, 251 (but see Section 3.4 for discussion of 251 and 551)
    // > E: 550, 551, 552, 553, 450, 451, 452, 503, 455, 555
    fn recipient(&mut self, path: RcptPath, params: RcptParameters,
                 send: &mut SendBuf) {
        let state = mem::replace(&mut self.state, State::Early);
        self.state = match state {
            State::MailRcpt(mut mail) => {
                if mail.rcpt(path, params, ProtoReply::new(send)) {
                    State::MailRcpt(mail)
                } else {
                    State::Session
                }
            }
            State::Closing => {
                Reply::reply(send, 503, (5,5,1), b"Please leave now\r\n");
                state
            }
            _ => {
                Reply::reply(send, 503, (5,5,1), b"Need MAIL first\r\n");
                state
            }
        }
    }

    // > I: 354 -> data -> S: 250
    // >                   E: 552, 554, 451, 452
    // >                   E: 450, 550 (rejections for policy reasons)
    // > E: 503, 554
    fn data(&mut self, send: &mut SendBuf) {
        let state = mem::replace(&mut self.state, State::Early);
        self.state = match state {
            State::MailRcpt(mut mail) => {
                match mail.data() {
                    None => {
                        Reply::reply(send, 554, (5,5,0),
                                     b"Transaction failed\r\n");
                        State::Session
                    }
                    Some(queue) => {
                        let mut reply = Reply::new(send, 354, None);
                        scribble!(&mut reply, b"Go ahead.\r\n");
                        State::MailData(queue)
                    }
                }
            }
            State::Closing => {
                Reply::reply(send, 503, (5,5,1), b"Please leave now\r\n");
                state
            }
            _ => {
                Reply::reply(send, 503, (5,5,1), b"Need RCPT first\r\n");
                state
            }
        }
    }

    // > S: 250
    fn reset(&mut self, send: &mut SendBuf) {
        Reply::reply(send, 250, (2,0,0), b"Ok\r\n");
        self.state = State::Session;
    }

    // > S: 250, 251, 252
    // > E: 550, 551, 553, 502, 504
    fn verify(&mut self, whom: Word, params: VrfyParameters,
              send: &mut SendBuf) {
        self.handler.verify(whom, params, ProtoReply::new(send));
    }

    // > S: 250, 252
    // > E: 550, 500, 502, 504
    fn expand(&mut self, whom: Word, params: ExpnParameters,
              send: &mut SendBuf) {
        self.handler.expand(whom, params, ProtoReply::new(send));
    }

    // > S: 211, 214
    // > E: 502, 504
    fn help(&mut self, what: Option<Word>, send: &mut SendBuf) {
        self.handler.help(what, ProtoReply::new(send));
    }

    // > S: 250
    fn noop(&mut self, send: &mut SendBuf) {
        Reply::reply(send, 250, (2, 0, 0), b"OK\r\n");
    }

    // > S: 221
    fn quit(&mut self, send: &mut SendBuf) {
        Reply::reply(send, 221, (2, 0, 0), b"Bye\r\n");
    }

    fn starttls(&mut self, send: &mut SendBuf) {
        let _ = send;
    }

    fn auth(&mut self, mechanism: &[u8], initial: Option<&[u8]>,
            send: &mut SendBuf) {
        let _ = (mechanism, initial, send);
    }
}


//------------ State --------------------------------------------------------

/// The state of an SMTP connection.
///
enum State<H: SessionHandler> {
    /// No Hello has been received yet
    Early,

    /// A Hello has been received and no mail transaction is going on
    Session,

    /// A mail transaction is beeing prepared (ie., we are collecting the
    /// RCPT commands)
    MailRcpt(H::Mail),

    /// A mail transaction's data is being received
    MailData(<<H as SessionHandler>::Mail as MailTransaction>::Data),

    /// Something went wrong and we are waiting for QUIT
    Closing,
}

impl<H: SessionHandler> State<H> {
    fn is_data(&self) -> bool {
        match *self {
            State::MailData(_) => true,
            _ => false
        }
    }
}


//------------ Reply --------------------------------------------------------

/// A type that will become a reply.
///
#[derive(Debug)]
pub struct ProtoReply<'a> {
    buf: &'a mut SendBuf,
}

impl <'a> ProtoReply<'a> {
    pub fn new(send: &'a mut SendBuf) -> Self {
        ProtoReply { buf: send }
    }

    pub fn start(self, code: u16, status: Option<(u16, u16, u16)>)
                 -> Reply<'a> {
        Reply::new(self.buf, code, status)
    }

    pub fn reply(self, code: u16, status: (u16, u16, u16), buf: &[u8]) {
        Reply::reply(self.buf, code, status, buf)
    }
}

/// A type to help writing a reply.
///
#[derive(Debug)]
pub struct Reply<'a> {
    buf: &'a mut SendBuf,
    code: u16,
    status: Option<(u16, u16, u16)>,

    /// Position of the space after the code in the last written prefix.
    sp: usize,

    /// Are we right after a CRLF?
    ///
    /// If yes, the next write starts a new line of a multiline reply.
    crlf: bool,
}

impl<'a> Reply<'a> {
    fn new(send: &'a mut SendBuf, code: u16, status: Option<(u16, u16, u16)>)
           -> Reply<'a> {
        let sp = write_prefix(send, code, status);
        Reply {
            buf: send,
            code: code,
            status: status,
            sp: sp,
            crlf: false,
        }
    }

    fn reply(send: &mut SendBuf, code: u16, status: (u16, u16, u16),
             buf: &[u8]) {
        let mut res = Reply::new(send, code, Some(status));
        scribble!(&mut res, buf);
    }

    fn error(send: &mut SendBuf, err: CommandError) {
        match err {
            CommandError::Unrecognized =>
                Reply::reply(send, 500, (5, 5, 2),
                             b"Command unrecognized\r\n"),
            CommandError::Parameters => 
                Reply::reply(send, 501, (5, 0, 1),
                             b"Syntax error in parameters\r\n"),
        }
    }
}

impl<'a> ::util::scribe::Scribe for Reply<'a> {
    fn scribble_bytes(&mut self, buf: &[u8]) {
        if buf.is_empty() { return; }
        for line in buf.split(|ch| *ch == b'\n') {
            if line.is_empty() { continue }
            if self.crlf {
                self.buf.update(self.sp, b'-');
                self.sp = write_prefix(self.buf, self.code, self.status);
                self.crlf = false;
            }
            self.buf.scribble_bytes(line);
            if line.last() == Some(&b'\r') {
                self.buf.scribble_octet(b'\n');
                self.crlf = true;
            }
        }
    }

    fn scribble_octet(&mut self, ch: u8) {
        if self.crlf {
            self.buf.update(self.sp, b'-');
            self.sp = write_prefix(self.buf, self.code, self.status);
            self.crlf = false;
        }
        self.buf.scribble_octet(ch)
    }
}

/// Writes the prefix for a line.
///
/// Returns the position of the space after the code.
///
fn write_prefix(send: &mut SendBuf, code: u16, status: Option<(u16, u16, u16)>)
                -> usize {
    send.scribble_octet(((code / 100) % 10) as u8 + b'0');
    send.scribble_octet(((code / 10) % 10) as u8 + b'0');
    send.scribble_octet((code % 10) as u8 + b'0');
    let res = send.len();
    send.scribble_octet(b' ');
    match status {
        None => { },
        Some((a, b, c)) => {
            scribble!(send, a, b".", b, b".", c, b" ")
        }
    };
    res
}

