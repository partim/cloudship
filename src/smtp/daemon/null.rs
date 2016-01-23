//! Trait implementations that just throw away data.

use std::io::{self, Write};
use openssl::x509::X509;
use smtp::protocol::{ExpnParameters, MailboxDomain, MailParameters,
                     RcptPath, RcptParameters, ReversePath, VrfyParameters,
                     Word}; 
use smtp::daemon::handler::{ServerHandler, SessionHandler,
                            MailTransaction, MailData};
use smtp::daemon::session::ProtoReply;

pub struct NullServer;

impl ServerHandler for NullServer {
    type Session = NullSession;

    fn start(&self) -> Self::Session {
        NullSession
    }
}


pub struct NullSession;

impl SessionHandler for NullSession {
    type Mail = NullTransaction;

    fn hello<'a>(&mut self, domain: MailboxDomain<'a>) {
        let _ = domain;
    }

    fn starttls(&mut self, peer_cert: X509) -> bool {
        let _ = peer_cert;
        true
    }

    fn mail<'a>(&self, path: ReversePath<'a>, params: MailParameters<'a>,
                reply: ProtoReply) -> Option<Self::Mail> {
        let _ = (path, params);
        reply.reply(205, (2,1,0), b"Ok\r\n");
        Some(NullTransaction)
    }

    fn verify<'a>(&self, whom: Word<'a>, params: VrfyParameters,
                  reply: ProtoReply) {
        let _ = (whom, params);
        reply.reply(252, (2, 7, 0),
                    b"VRFY administratively disable\r\n");
    }

    fn expand<'a>(&self, whom: Word<'a>, params: ExpnParameters,
                  reply: ProtoReply) {
        let _ = (whom, params);
        reply.reply(252, (2, 7, 0),
                    b"EPXN administratively disable\r\n");
    }

    fn help<'a>(&self, what: Option<Word<'a>>, reply: ProtoReply) {
        let _ = what;
        reply.reply(214, (2, 0, 0),
                    b"Some helpful text will appear here soon.\r\n");
    }
}


pub struct NullTransaction;

impl MailTransaction for NullTransaction {
    type Data = NullData;

    fn rcpt<'b>(&mut self, path: RcptPath<'b>, params: RcptParameters<'b>,
                reply: ProtoReply) -> bool {
        let _ = (path, params);
        reply.reply(250, (2,1,0), b"Ok\r\n");
        true
    }

    fn data(&mut self) -> Option<Self::Data> {
        Some(NullData)
    }
}


pub struct NullData;

impl MailData for NullData {
    fn done(self, reply: ProtoReply) {
        reply.reply(250, (2,0,0), b"Ok\r\n");
    }
}

impl Write for NullData {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
