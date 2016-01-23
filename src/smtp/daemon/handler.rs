//! Traits for handling SMTP sessions.

use std::io::Write;
use std::marker::Sized;
use openssl::x509::X509;
use smtp::protocol::{ExpnParameters, MailboxDomain, MailParameters,
                     RcptPath, RcptParameters, ReversePath, VrfyParameters,
                     Word}; 
use smtp::daemon::session::ProtoReply;
use util::scribe::Scribe;

pub trait ServerHandler: Sized {
    type Session: SessionHandler;

    fn start(&self) -> Self::Session;
}

pub trait SessionHandler: Sized {
    type Mail: MailTransaction;
//    type Auth: SaslTransaction;

    fn hello<'a>(&mut self, domain: MailboxDomain<'a>);
    fn scribble_hostname<S: Scribe>(&self, scribe: &mut S);
    fn message_size_limit(&self) -> u64;

    fn starttls(&mut self, peer_cert: X509) -> bool;
  
/*
    fn startauth(&mut self) -> Self::Auth;
    fn finishauth(&mut self, auth: Self::Auth) -> bool;
*/

    fn mail<'a>(&self, path: ReversePath<'a>, params: MailParameters<'a>,
                reply: ProtoReply) -> Option<Self::Mail>;

    fn verify<'a>(&self, whom: Word<'a>, params: VrfyParameters,
                  reply: ProtoReply);
    fn expand<'a>(&self, whom: Word<'a>, params: ExpnParameters,
                  reply: ProtoReply);

    fn help<'a>(&self, what: Option<Word<'a>>, reply: ProtoReply);
}

pub trait MailTransaction: Sized {
    type Data: MailData;

    fn rcpt<'a>(&mut self, path: RcptPath<'a>, params: RcptParameters<'a>,
                reply: ProtoReply) -> bool;
    fn data(&mut self) -> Option<Self::Data>;
    fn rset(self) { }
}

pub trait MailData: Write + Sized {
    fn rset(self) { }
    fn done(self, reply: ProtoReply);
}

// XXX Placeholder for now
trait SaslTransaction { }

