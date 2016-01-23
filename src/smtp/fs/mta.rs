//! Handler implementations for an MTA.
//!

use std::io::{self, Write};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use openssl::x509::X509;
use smtp::daemon::handler::{ServerHandler, SessionHandler, MailTransaction,
                            MailData};
use smtp::daemon::session::ProtoReply;
use smtp::protocol::{ExpnParameters, MailboxDomain, MailParameters,
                     RcptPath, RcptParameters, ReversePath, VrfyParameters,
                     Word}; 

pub struct Config {
    queue_dir: PathBuf,
}

pub struct Server {
    config: Rc<Config>,
}

impl Server {
    pub fn new<P: AsRef<Path>>(queue_dir: P) -> Server {
        let queue_dir = queue_dir.as_ref().to_path_buf();
        Server {
            config: Rc::new(Config { queue_dir: queue_dir })
        }
    }
}

impl ServerHandler for Server {
    type Session = Session;

    fn start(&self) -> Self::Session {
        Session::new(self.config.clone())
    }
}


pub struct Session {
    config: Rc<Config>,
}

impl Session {
    fn new(config: Rc<Config>) -> Self {
        Session { config: config }
    }
}

impl SessionHandler for Session {
    type Mail = Mail;

    fn hello<'b>(&mut self, domain: MailboxDomain<'b>) {
        info!("Client hello from {}", domain);
    }

    fn starttls(&mut self, peer_cert: X509) -> bool {
        let _ = peer_cert;
        true
    }

    fn mail<'b>(&self, path: ReversePath<'b>, params: MailParameters<'b>,
                reply: ProtoReply) -> Option<Self::Mail> {
        reply.reply(205, (2,1,0), b"Ok\r\n");
        Some(Mail::new(self.config.clone(), path, params))
    }

    fn verify<'b>(&self, whom: Word<'b>, params: VrfyParameters,
                  reply: ProtoReply) {
        let _ = whom;
        let _ = params;
        let mut reply = reply.start(252, Some((2, 5, 2)));
        scribble!(&mut reply, b"VRFY administratively disable\r\n");
    }

    fn expand<'b>(&self, whom: Word<'b>, params: ExpnParameters,
                  reply: ProtoReply) {
        let _ = whom;
        let _ = params;
        let mut reply = reply.start(252, Some((2, 5, 2)));
        scribble!(&mut reply, b"VRFY administratively disable\r\n");
    }

    fn help<'b>(&self, what: Option<Word<'b>>, reply: ProtoReply) {
        let _ = what;
        let mut reply = reply.start(214, Some((2, 0, 0)));
        scribble!(&mut reply, b"Some helpful text will appear here soon.\r\n");
    }
}


pub struct Mail {
    config: Rc<Config>,
}

impl Mail {
    fn new<'b>(config: Rc<Config>, path: ReversePath<'b>,
           params: MailParameters<'b>) -> Self {
        let _ = path;
        let _ = params;
        Mail { config: config }
    }
}

impl MailTransaction for Mail {
    type Data = Data; 

    fn rcpt<'b>(&mut self, path: RcptPath<'b>, params: RcptParameters<'b>,
                reply: ProtoReply) -> bool {
        let _ = (path, params);
        reply.reply(250, (2,1,0), b"Ok\r\n");
        true
    }

    fn data(&mut self) -> Option<Self::Data> {
        Some(Data::new("/tmp/cloudship.test"))
    }

    fn rset(self) {
    }
}


pub struct Data {
    file: File,
}

impl Data {
    fn new<P: AsRef<Path>>(path: P) -> Data {
        Data { file: File::create(path.as_ref()).unwrap() }
    }
}

impl MailData for Data {
    fn rset(self) {
    }

    fn done(self, reply: ProtoReply) {
        reply.reply(250, (2,0,0), b"Ok\r\n");
    }
}

impl Write for Data {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

