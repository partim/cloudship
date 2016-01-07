use std::io::{self, Cursor};
use std::ptr;
use bytes::{Buf};
use mio::{TryRead, TryWrite};
use mio::tcp::TcpStream;
use tick::{self, Interest};
use super::Config;
use super::session::Session;
use ::util::scribe::{Scribe, Scribble};


/// A connection to an SMTP daemon
///
pub struct Connection<'a> {
    session: Session<'a>,
    direction: Direction,
    recv: RecvBuf,
    send: SendBuf,
}

impl<'a> Connection<'a> {
    fn new(config: &'a Config) -> Connection<'a> {
        Connection {
            session: Session::new(config),
            direction: Direction::Reply,
            recv: RecvBuf::new(),
            send: build_greeting(config),
        }
    }

    pub fn create(config: &'a Config) -> (Connection<'a>, Interest) {
        let conn = Connection::new(config);
        let interest = conn.interest();
        (conn, interest)
    }

    fn interest(&self) -> Interest {
        match self.direction {
            Direction::Receive => Interest::Read,
            Direction::Reply => Interest::Write,
            Direction::Closing => Interest::Write,
            Direction::Closed => Interest::Remove,
        }
    }

    fn process_read(&mut self) {
        let (session, recv, send) = (&mut self.session, &mut self.recv,
                                     &mut self.send);
        self.direction = session.process(recv, send);
    }
}

impl<'a> tick::Protocol<TcpStream> for Connection<'a> {
    fn on_readable(&mut self, transport: &mut TcpStream) -> Interest {
        match self.recv.try_read(transport) {
            Ok(Some(0)) => self.direction = Direction::Closed,
            Ok(Some(_)) => self.process_read(),
            Ok(None) => { },
            Err(e) => {
                debug!("SMTP connection read error: {:?}", e);
                self.direction = Direction::Closed
            }
        }

        self.interest()
    }

    fn on_writable(&mut self, transport: &mut TcpStream) -> Interest {
        match self.send.try_write(transport) {
            Ok(true) => {
                self.direction = match self.direction {
                    Direction::Closing => Direction::Closed,
                    Direction::Reply => Direction::Receive,
                    _ => unreachable!()
                };
            }
            Ok(false) => { }
            Err(e) => {
                debug!("SMTP connection write error: {:?}", e);
                self.direction = Direction::Closed
            }
        }
        self.interest()
    }

    fn on_error(&mut self, err: tick::Error) {
        debug!("Error on SMTP connection: {:?}", err);
    }
}

//------------ Direction ----------------------------------------------------

#[derive(Debug)]
pub enum Direction {
    /// Receive and process data.
    Receive,

    /// Write all the data, then return to `Direction::Receive`.
    Reply,

    /// Write all data, then move to `Direction::Closed`.
    Closing,

    /// Close the connection.
    Closed,
}


//------------ RecvBuf ------------------------------------------------------

/// The buffer to receive data into and parse it out of again.
///
#[derive(Debug)]
pub struct RecvBuf {
    inner: Vec<u8>,
    rpos: usize,
}

impl RecvBuf {
    fn new() -> RecvBuf {
        RecvBuf {
            inner: Vec::with_capacity(1024),
            rpos: 0,
        }
    }

    fn try_read(&mut self, transport: &mut TcpStream)
                -> io::Result<Option<usize>> {
        transport.try_read_buf(&mut self.inner)
    }

    pub fn advance(&mut self, len: usize) {
        self.rpos += len
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner[self.rpos..]
    }

    pub fn is_empty(&self) -> bool {
        self.rpos == self.inner.len()
    }

    pub fn len(&self) -> usize {
        self.inner.len() - self.rpos
    }
}


//------------ SendBuf ------------------------------------------------------

/// The buffer that stores responses and eventually sends them.
///
#[derive(Debug)]
pub struct SendBuf {
    inner: Cursor<Vec<u8>>
}

impl SendBuf {
    fn new() -> SendBuf {
        SendBuf {
            inner: Cursor::new(Vec::new())
        }
    }

    // Ok(true) .. we are done, Ok(false) .. keep writing
    fn try_write(&mut self, transport: &mut TcpStream)
                -> io::Result<bool> {
        match try!(transport.try_write_buf(&mut self.inner)) {
            Some(_) => {
                if !self.inner.has_remaining() {
                    self.inner.set_position(0);
                    self.inner.get_mut().clear();
                    Ok(true)
                }
                else { Ok(false) }
            }
            None => Ok(false)
        }
    }

    pub fn len(&self) -> usize { self.inner.get_ref().len() }

    pub fn update(&mut self, pos: usize, ch: u8) {
        self.inner.get_mut()[pos] = ch
    }
}

impl Scribe for SendBuf {
    fn scribble_bytes(&mut self, buf:&[u8]) {
        let vec = self.inner.get_mut();
        let len = vec.len();
        vec.reserve(buf.len());
        unsafe {
            ptr::copy(buf.as_ptr(), vec.get_unchecked_mut(len), buf.len());
            vec.set_len(len + buf.len());
        }
    }

    fn scribble_octet(&mut self, v: u8) {
        self.inner.get_mut().push(v);
    }
}

//------------ Helpers ------------------------------------------------------

fn build_greeting(config: &Config) -> SendBuf {
    let mut res = SendBuf::new();
    scribble!(&mut res, b"220 ", &config.hostname, b" ESMTP ",
                        &config.systemname, b"\r\n");
    res
}
