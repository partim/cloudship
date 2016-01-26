use std::cmp::min;
use std::io::{self, Cursor};
use std::ptr;
use bytes::{Buf};
use mio::{TryRead, TryWrite};
use tick::{self, Interest, Transport};
use super::handler::SessionHandler;
use super::session::Session;
use ::util::scribe::Scribe;


/// A connection to an SMTP daemon
///
pub struct Connection<H: SessionHandler> {
    session: Session<H>,
    direction: Direction,
    recv: RecvBuf,
    send: SendBuf,
}

impl<H: SessionHandler> Connection<H> {
    fn new(handler: H) -> Self {
        Connection {
            session: Session::new(handler),
            direction: Direction::Reply,
            recv: RecvBuf::new(),
            send: SendBuf::new(),
        }
    }

    pub fn create(handler: H) -> (Connection<H>, Interest) {
        let mut conn = Connection::new(handler);
        conn.direction = conn.session.start(&mut conn.send);
        let interest = conn.interest();
        (conn, interest)
    }

    fn interest(&self) -> Interest {
        match self.direction {
            Direction::Receive => Interest::Read,
            Direction::Reply => Interest::Write,
            Direction::Closing => Interest::Write,
            Direction::Closed => Interest::Remove,
            Direction::StartTls => unreachable!(),
        }
    }

    fn process_read(&mut self) {
        let (session, recv, send) = (&mut self.session, &mut self.recv,
                                     &mut self.send);
        self.direction = session.process(recv, send);
    }
}

impl<H: SessionHandler, T: Transport> tick::Protocol<T> for Connection<H> {
    fn on_readable(&mut self, transport: &mut T) -> Interest {
        match self.recv.try_read(transport) {
            Ok(Some(0)) => self.direction = Direction::Closed,
            Ok(Some(_)) => self.process_read(),
            Ok(None) => { },
            Err(e) => {
                debug!("SMTP connection read error: {:?}", e);
                self.direction = Direction::Closed
            }
        }

        if self.direction == Direction::StartTls {

        }

        self.interest()
    }

    fn on_writable(&mut self, transport: &mut T) -> Interest {
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

#[derive(Debug, PartialEq)]
pub enum Direction {
    /// Receive and process data.
    Receive,

    /// Write all the data, then return to `Direction::Receive`.
    Reply,

    /// Write all data, then move to `Direction::Closed`.
    Closing,

    /// Start TLS handshake.
    StartTls,

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

    fn try_read<T: TryRead>(&mut self, transport: &mut T)
                -> io::Result<Option<usize>> {
        transport.try_read_buf(&mut self.inner)
    }

    pub fn advance(&mut self, len: usize) {
        self.rpos = min(self.inner.len(), self.rpos + len);
        if self.is_empty() {
            self.clear();
        }
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

    pub fn clear(&mut self) {
        self.inner.clear();
        self.rpos = 0;
    }

    /// Finds the index of `CRLF "." CRLF` in the buffer.
    ///
    pub fn find_data_end(&self) -> Option<usize> {
        let slice = self.as_slice();
        for i in 0..slice.len() - 5 {
            if &slice[i..i+5] == b"\r\n.\r\n" {
                return Some(i)
            }
        }
        None
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
    fn try_write<T: TryWrite>(&mut self, transport: &mut T)
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

    pub fn is_empty(&self) -> bool {
        (self.inner.get_ref().len() as u64) == self.inner.position()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner.get_ref()[self.inner.position() as usize..]
    }

    pub fn advance(&mut self, by: usize) {
        use std::io::Seek;
        let _ = self.inner.seek(::std::io::SeekFrom::Current(by as i64))
                          .unwrap();
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


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use nom::IResult::Done;
    use smtp::daemon::session::Session;
    use smtp::daemon::null::NullSession;
    use smtp::protocol::Reply;
    use super::*;

    /// Like a regular connection but without all the tedious IO.
    ///
    pub struct TestConnection {
        session: Session<NullSession>,
        direction: Direction,
        recv: RecvBuf,
        send: SendBuf,
        bcc: Vec<u8>,
    }

    impl TestConnection {
        pub fn new() -> Self {
            let handler = NullSession;
            let mut res = TestConnection {
                session: Session::new(handler),
                direction: Direction::Reply,
                recv: RecvBuf::new(),
                send: SendBuf::new(),
                bcc: Vec::new()
            };
            res.session.start(&mut res.send);
            res
        }

        /// Send *data* to the session.
        pub fn send(&mut self, data: &[u8]) {
            let mut buf = ::bytes::ByteBuf::from_slice(data);
            self.recv.try_read(&mut buf).unwrap();
            for line in data.split(|ch| *ch == b'\n') {
                if !line.is_empty() {
                    self.bcc.extend_from_slice(b">>> C: ");
                    self.bcc.extend_from_slice(line);
                    self.bcc.push(b'\n');
                }
            }
            self.direction = self.session.process(&mut self.recv,
                                                  &mut self.send);
        }

        /*
        pub fn recv(&mut self) -> Vec<u8> {
            let mut buf = Vec::new();
            self.send.try_write(&mut buf).unwrap();
            for line in buf.split(|ch| *ch == b'\n') {
                if !line.is_empty() {
                    self.bcc.extend_from_slice(b">>> S: ");
                    self.bcc.extend_from_slice(line);
                    self.bcc.push(b'\n');
                }
            }
            buf
        }
        */

        pub fn advance_send(&mut self, len: usize) {
            for line in self.send.as_slice()[..len].split(|ch| *ch == b'\n') {
                if !line.is_empty() {
                    self.bcc.extend_from_slice(b">>> S: ");
                    self.bcc.extend_from_slice(line);
                    self.bcc.push(b'\n');
                }
            }
            self.send.advance(len);
        }

        pub fn recv_reply(&mut self) -> Result<Reply, ()> {
            let len;
            let res;
            {
                let slice = self.send.as_slice();
                match Reply::parse(slice) {
                    Done(rest, right) => {
                        len = slice.len() - rest.len();
                        res=right
                    }
                    _ => { return Err(()) }
                }
            }
            self.advance_send(len);
            Ok(res)
        }

        pub fn assert_reply(&mut self, code: u16,
                            status: Option<(u16, u16, u16)>) {
            match self.recv_reply() {
                Ok(reply) => {
                    assert_eq!(reply.code, code);
                    assert_eq!(reply.status, status);
                }
                Err(()) => { panic!("No reply") }
            }
        }

        pub fn dump(&self) {
            println!("{}", String::from_utf8_lossy(&self.bcc));
        }
    }

    #[test]
    fn test() {
        let mut conn = TestConnection::new();
        conn.assert_reply(220, None);
        conn.send(b"EHLO localhost.local\r\n");
        conn.assert_reply(250, None);
        conn.dump();
    }
}
