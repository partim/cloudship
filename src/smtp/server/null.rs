
use std::net::SocketAddr;
use netmachines::sockets::Certificate;
use rotor::{Notifier, Void};
use ::smtp::syntax;
use super::protocol::{AncillaryHandler, DataHandler, Hesitant, MailHandler,
                      Protocol, SessionHandler};
use super::reply::ReplyBuf;


//------------ NullProtocol --------------------------------------------------

pub struct NullProtocol;

impl Protocol for NullProtocol {
    type Session = Self;
    type Mail = Self;
    type Data = Self;

    fn accept(&mut self, _addr: &SocketAddr) -> Option<()> {
        Some(())
    }
}


impl AncillaryHandler for NullProtocol {
    type Verify = Void;
    type Expand = Void;
    type Help = Void;

    fn verify(self, _what: syntax::Word, _params: syntax::VrfyParameters,
              reply: ReplyBuf) -> Hesitant<Self, Void> {
        reply.reply(252, (2, 7, 0), b"VRFY administratively disabled\r\n");
        Hesitant::Final(self)
    }

    fn expand(self, _what: syntax::Word, _params: syntax::ExpnParameters,
              reply: ReplyBuf) -> Hesitant<Self, Void> {
        reply.reply(252, (2, 7, 0), b"EXPN administratively disabled\r\n");
        Hesitant::Final(self)
    }

    fn help(self, _what: Option<syntax::Word>, reply: ReplyBuf)
            -> Hesitant<Self, Void> {
        reply.reply(214, (2, 0, 0),
                   b"This SMTP server eats your mail.\r\n");
        Hesitant::Final(self)
    }
}


impl SessionHandler<NullProtocol> for NullProtocol {
    type Seed = ();
    type Start = Void;
    type Hello = Void;
    type CheckTls = Void;
    type Mail = Void;

    fn start(_seed: (), _notifier: Notifier) -> Hesitant<Option<Self>, Void> {
        Hesitant::Final(Some(NullProtocol))
    }

    fn hello(self, _domain: syntax::MailboxDomain)
             -> Hesitant<Option<Self>, Void> {
        Hesitant::Final(Some(self))
    }

    fn check_tls<C: Certificate>(self, _peer_cert: Option<C>)
                                 -> Hesitant<Option<Self>, Void> {
        Hesitant::Final(Some(self))
    }

    fn mail(self, _path: syntax::ReversePath, _params: syntax::MailParameters,
            reply: ReplyBuf) -> Hesitant<Result<Self, Self>, Void> {
        reply.reply(250, (2, 1, 0), b"Ok\r\n");
        Hesitant::Final(Ok(self))
    }
}


impl MailHandler<NullProtocol> for NullProtocol {
    type Recipient = Void;
    type Data = Void;

    fn recipient(self, _path: syntax::RcptPath,
                 _params: syntax::RcptParameters, reply: ReplyBuf)
                 -> Hesitant<Result<Self, NullProtocol>, Void> {
        reply.reply(250, (2, 1, 0), b"Ok\r\n");
        Hesitant::Final(Ok(self))
    }

    fn data(self) -> Hesitant<Result<Self, Self>, Void> {
        Hesitant::Final(Ok(self))
    }

    fn reset(self) -> Self {
        self
    }
}


impl DataHandler<NullProtocol> for NullProtocol {
    type Complete = Void;

    fn chunk(&mut self, _data: &[u8]) {
    }

    fn complete(self, reply: ReplyBuf) -> Hesitant<Self, Void> {
        reply.reply(250, (2, 1, 0), b"Ok\r\n");
        Hesitant::Final(self)
    }
}
