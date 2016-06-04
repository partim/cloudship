use std::cmp::min;
use std::io;
use std::ptr;
use bytes::buf::Buf;
use mio::{TryRead, TryWrite};
use ::util::scribe::Scribe;
use super::reply::Reply;

//------------ RecvBuf ------------------------------------------------------

/// The buffer to receive data into and parse it out of again.
///
#[derive(Debug)]
pub struct RecvBuf {
    inner: Vec<u8>,
    rpos: usize,
}

impl RecvBuf {
    pub fn new() -> RecvBuf {
        RecvBuf {
            inner: Vec::with_capacity(1024),
            rpos: 0,
        }
    }

    pub fn try_read<T: TryRead>(&mut self, transport: &mut T)
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
        if slice.len() >= 5 {
            for i in 0..slice.len() - 4 {
                if &slice[i..i+5] == b"\r\n.\r\n" {
                    return Some(i)
                }
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
    inner: io::Cursor<Vec<u8>>
}

impl SendBuf {
    pub fn new() -> SendBuf {
        SendBuf {
            inner: io::Cursor::new(Vec::new())
        }
    }

    pub fn reply(&mut self, code: u16, status: (u8, u16, u16), text: &[u8]) {
        Reply::reply(self, code, status, text)
    }

    // Ok(true) .. we are done, Ok(false) .. keep writing
    pub fn try_write<T: TryWrite>(&mut self, transport: &mut T)
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
