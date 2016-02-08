//! Building and queueing up replies.
//!

use util::scribe::{Scribe, Scribble};
use super::buf::SendBuf;


//------------ ReplyBuf -----------------------------------------------------

/// A type that will become a reply.
///
pub struct ReplyBuf<'a> {
    buf: &'a mut SendBuf,
}

impl<'a> ReplyBuf<'a> {
    /// Creates a new reply buf from an output buffer.
    ///
    pub fn new(send: &'a mut SendBuf) -> Self {
        ReplyBuf { buf: send }
    }

    /// Starts a reply.
    ///
    /// Use this method if you want to scribble the text of the reply.
    /// The argument *code* is the three digit code while *status* is
    /// the optional enhanced status code.
    ///
    pub fn start(self, code: u16, status: Option<(u8, u16, u16)>)
                 -> Reply<'a> {
        Reply::new(self.buf, code, status)
    }

    /// Buffers a reply.
    ///
    /// Use this method if you have all your text already available.
    /// The argument *code* is the three digit code while *status* is
    /// the enhanced status code. Finally, *text* is the text.
    /// You have to include the final `b"\r\n"` in that text.
    ///
    pub fn reply(self, code: u16, status: (u8, u16, u16),
                 text: &[u8]) {
        Reply::reply(self.buf, code, status, text)
    }
}


//------------ Reply --------------------------------------------------------

/// A type to help writing a reply.
///
#[derive(Debug)]
pub struct Reply<'a> {
    buf: &'a mut SendBuf,
    code: u16,
    status: Option<(u8, u16, u16)>,

    /// Position of the space after the code in the last written prefix.
    sp: usize,

    /// Are we right after a CRLF?
    ///
    /// If yes, the next write starts a new line of a multiline reply.
    crlf: bool,
}

impl<'a> Reply<'a> {
    pub fn new(send: &'a mut SendBuf, code: u16, status: Option<(u8, u16, u16)>)
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

    pub fn reply(send: &mut SendBuf, code: u16, status: (u8, u16, u16),
                 text: &[u8]) {
        let mut res = Reply::new(send, code, Some(status));
        scribble!(&mut res, text);
    }
}

impl<'a> ::util::scribe::Scribe for Reply<'a> {
    fn scribble_bytes(&mut self, text: &[u8]) {
        if text.is_empty() { return; }
        for line in text.split(|ch| *ch == b'\n') {
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
fn write_prefix(send: &mut SendBuf, code: u16,
                status: Option<(u8, u16, u16)>) -> usize {
    assert!(code >= 200 && code <= 599);
    code.scribble(send);
    let res = send.len();
    send.scribble_octet(b' ');
    match status {
        None => { },
        Some((a, b, c)) => {
            scribble!(send, a as u16, b".", b, b".", c, b" ")
        }
    };
    res
}


