//! Trait implementations that just throw away data.

use std::marker::PhantomData;
use openssl::ssl::SslContext;
use openssl::x509::X509;
use rotor::Notifier;
use super::super::syntax;
use super::protocol::{Context, Hesitant, Protocol, MailTransaction};
use super::protocol::Hesitant::Continue;
use super::reply::ReplyBuf;


pub struct NullContext {
    ssl_context: SslContext,
}

impl NullContext {
    pub fn new(ssl_context: SslContext) -> Self {
        NullContext { ssl_context: ssl_context }
    }
}

impl Context for NullContext {
    fn ssl_context(&self) -> SslContext { self.ssl_context.clone() }
    fn hostname(&self) -> &[u8] { b"localhost.local" }
    fn systemname(&self) -> &[u8] { b"Cloudship" }
    fn message_size_limit(&self) -> u64 { 10485760u64 }
}


pub struct NullProtocol<Ctx: Context> {
    phantom: PhantomData<Ctx>,
}

impl<Ctx: Context> NullProtocol<Ctx> {
    pub fn new() -> Self {
        NullProtocol { phantom: PhantomData }
    }
}


impl<Ctx: Context> Protocol for NullProtocol<Ctx> {
    type Context = Ctx;
    type Mail = NullMail;

    fn create(context: &Self::Context, notifier: Notifier) -> Option<Self> {
        let _ = (context, notifier);
        Some(NullProtocol::new())
    }

    fn hello(self, domain: syntax::MailboxDomain) -> Hesitant<Self> {
        let _ = domain;
        Continue(self)
    }

    fn starttls(self, peer_cert: Option<X509>) -> Hesitant<Self> {
        let _ = peer_cert;
        Continue(self)
    }

    fn mail(&self) -> Self::Mail {
        NullMail
    }

    fn verify(self, what: syntax::Word, params: syntax::VrfyParameters,
              send: ReplyBuf) -> Hesitant<Self> {
        let _ = (what, params);
        send.reply(252, (2, 7, 0), b"VRFY administratively disabled\r\n");
        Continue(self)
    }

    fn expand(self, what: syntax::Word, params: syntax::ExpnParameters,
              send: ReplyBuf) -> Hesitant<Self> {
        let _ = (what, params);
        send.reply(252, (2, 7, 0), b"EXPN administratively disabled\r\n");
        Continue(self)
    }

    fn help(self, what: Option<syntax::Word>, send: ReplyBuf)
            -> Hesitant<Self> {
        let _ = what;
        send.reply(214, (2, 0, 0),
                   b"This SMTP server eats your mail.\r\n");
        Continue(self)
    }
}


pub struct NullMail;

impl MailTransaction for NullMail {
    fn mail(self, path: syntax::ReversePath, params: syntax::MailParameters,
            send: ReplyBuf) -> Hesitant<Self> {
        let _ = (path, params);
        send.reply(250, (2, 1, 0), b"Ok\r\n");
        Continue(self)
    }

    fn recipient(self, path: syntax::RcptPath,
                 params: syntax::RcptParameters, send: ReplyBuf)
                 -> Hesitant<Self> {
        let _ = (path, params);
        send.reply(250, (2, 1, 0), b"Ok\r\n");
        Continue(self)
    }

    fn data(self) -> Hesitant<Self> {
        Continue(self)
    }

    fn chunk(&mut self, data: &[u8]) {
        let _ = data;
    }
    
    fn complete(self, send: ReplyBuf) -> Hesitant<Self> {
        send.reply(250, (2, 1, 0), b"Ok\r\n");
        Continue(self)
    }

    fn reset(self) -> Hesitant<Self> {
        Continue(self)
    }
}
