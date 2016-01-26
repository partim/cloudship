
use std::io::{self, Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use mio::TryAccept;
use mio::tcp::{TcpListener, TcpStream};
use openssl::ssl::{IntoSsl, MaybeSslStream, Ssl, SslContext, SslStream};
use openssl::ssl::error::SslError;


/// A TcpListener for streams that can start TLS later.
///
pub struct StartTlsListener {
    ctx: Arc<SslContext>,
    lsnr: TcpListener,
}

impl StartTlsListener {
    fn new(ctx: Arc<SslContext>, lsnr: TcpListener) -> StartTlsListener {
        StartTlsListener { ctx: ctx, lsnr: lsnr }
    }

    fn accept(&self) -> io::Result<Option<(StartTlsStream, SocketAddr)>> {
        self.lsnr.accept().map(
            |res| res.map(|(stream, addr)|
                (StartTlsStream::new(self.ctx.clone(), stream), addr)))
    }
}

impl TryAccept for StartTlsListener {
    type Output = StartTlsStream;

    fn accept(&self) -> io::Result<Option<Self::Output>> {
        StartTlsListener::accept(self).map(|r| r.map(|(s, _)| s))
    }
}


/// A TcpStream for stream taht can start TLS later.
///
pub struct StartTlsStream {
    ctx: Arc<SslContext>,
    stream: Option<MaybeSslStream<TcpStream>>,
}

impl StartTlsStream {
    fn new(ctx: Arc<SslContext>, stream: TcpStream) -> StartTlsStream {
        StartTlsStream { ctx: ctx,
                         stream: Some(MaybeSslStream::Normal(stream)) }
    }

    fn wrap_client(&mut self) -> Result<(), SslError> {
        self.wrap(SslStream::<TcpStream>::connect::<&SslContext>)
    }

    fn wrap_server(&mut self) -> Result<(), SslError> {
        self.wrap(SslStream::<TcpStream>::accept::<&SslContext>)
    }


    fn wrap<'a, F>(&'a mut self, f: F) -> Result<(), SslError>
            where F: Fn(&'a SslContext, TcpStream)
                              -> Result<SslStream<TcpStream>, SslError> {
        let stream = mem::replace(&mut self.stream, None);
        let (new_stream, res) = match stream {
            Some(MaybeSslStream::Normal(s)) => {
                let ctx: &'a SslContext = &self.ctx;
                match f(ctx, s) {
                    Ok(ss) => (Some(MaybeSslStream::Ssl(ss)), Ok(())),
                    Err(e) => (None, Err(e))
                }
            }
            Some(MaybeSslStream::Ssl(s)) => {
                (Some(MaybeSslStream::Ssl(s)), Ok(()))
            }
            None => (None,
                     Err(SslError::StreamError(
                             io::Error::new(io::ErrorKind::ConnectionAborted,
                                            ""))))
        };
        self.stream = new_stream;
        res
    }

}

impl Read for StartTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.stream {
            Some(ref mut s) => s.read(buf),
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                                       "")),
        }
    }
}

impl Write for StartTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.stream {
            Some(ref mut s) => s.write(buf),
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                                       "")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.stream {
            Some(ref mut s) => s.flush(),
            None => Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                                       "")),
        }
    }
}
