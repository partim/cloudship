
use std::io::{self, Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use mio;
use mio::tcp::{TcpListener, TcpStream};
use openssl::ssl::{MaybeSslStream, SslContext, SslStream};
use openssl::ssl::error::SslError;


/// A TcpListener for streams that can start TLS later.
///
pub struct StartTlsListener {
    ctx: Arc<SslContext>,
    lsnr: TcpListener,
}

impl StartTlsListener {
    pub fn new(ctx: Arc<SslContext>, lsnr: TcpListener) -> StartTlsListener {
        StartTlsListener { ctx: ctx, lsnr: lsnr }
    }

    pub fn accept(&self) -> io::Result<Option<(StartTlsStream, SocketAddr)>> {
        self.lsnr.accept().map(
            |res| res.map(|(stream, addr)|
                (StartTlsStream::new(self.ctx.clone(), stream), addr)))
    }
}

impl mio::TryAccept for StartTlsListener {
    type Output = StartTlsStream;

    fn accept(&self) -> io::Result<Option<Self::Output>> {
        StartTlsListener::accept(self).map(|r| r.map(|(s, _)| s))
    }
}

impl mio::Evented for StartTlsListener {
    fn register(&self, selector: &mut mio::Selector, token: mio::Token,
                interest: mio::EventSet, opts: mio::PollOpt)
                -> io::Result<()> {
        self.lsnr.register(selector, token, interest, opts)
    }

    fn reregister(&self, selector: &mut mio::Selector, token: mio::Token,
                  interest: mio::EventSet, opts: mio::PollOpt)
                  -> io::Result<()> {
        self.lsnr.reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut mio::Selector) -> io::Result<()> {
        self.lsnr.deregister(selector)
    }
}


/// A TcpStream for stream that can start TLS later.
///
pub struct StartTlsStream {
    ctx: Arc<SslContext>,
    stream: MaybeSslStream<TcpStream>,
}

impl StartTlsStream {
    fn new(ctx: Arc<SslContext>, stream: TcpStream) -> StartTlsStream {
        StartTlsStream { ctx: ctx,
                         stream: MaybeSslStream::Normal(stream) }
    }

    pub fn wrap_client(&mut self) -> Result<(), SslError> {
        self.wrap(SslStream::<TcpStream>::connect::<&SslContext>)
    }

    pub fn wrap_server(&mut self) -> Result<(), SslError> {
        self.wrap(SslStream::<TcpStream>::accept::<&SslContext>)
    }

    fn wrap<'a, F>(&'a mut self, f: F) -> Result<(), SslError>
            where F: Fn(&'a SslContext, TcpStream)
                              -> Result<SslStream<TcpStream>, SslError> {
        
        let stream = match self.stream {
            MaybeSslStream::Ssl(_) => { return Ok(()) }
            MaybeSslStream::Normal(ref s) => {
                match s.try_clone() {
                    Ok(s) => s,
                    Err(e) => { return Err(SslError::StreamError(e)) }
                }
            }
        };
        let stream = mem::replace(&mut self.stream,
                                  MaybeSslStream::Normal(stream));
        let stream = match stream {
            MaybeSslStream::Normal(s) => s,
            _ => unreachable!()
        };
        let ctx: &'a SslContext = &self.ctx;
        let stream = try!(f(ctx, stream));
        self.stream = MaybeSslStream::Ssl(stream);
        Ok(())
    }

    fn tcp_stream<'a>(&'a self) -> &'a TcpStream {
        match self.stream {
            MaybeSslStream::Normal(ref s) => s,
            MaybeSslStream::Ssl(ref s) => s.get_ref(),
        }
    }
}

impl Read for StartTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for StartTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl mio::Evented for StartTlsStream {
    fn register(&self, selector: &mut mio::Selector, token: mio::Token,
                interest: mio::EventSet, opts: mio::PollOpt)
                -> io::Result<()> {
        self.tcp_stream().register(selector, token, interest, opts)
    }

    fn reregister(&self, selector: &mut mio::Selector, token: mio::Token,
                  interest: mio::EventSet, opts: mio::PollOpt)
                  -> io::Result<()> {
        self.tcp_stream().reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut mio::Selector) -> io::Result<()> {
        self.tcp_stream().deregister(selector)
    }
}

