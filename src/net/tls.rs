
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use rotor::mio;
use rotor::mio::tcp::{TcpListener, TcpStream};
use openssl::ssl::{MaybeSslStream, SslContext, SslStream};
use openssl::ssl::error::SslError;
use openssl::x509::X509;


/// A TcpListener for streams that can start TLS later.
///
pub struct StartTlsListener(TcpListener);

impl StartTlsListener {
    pub fn new(lsnr: TcpListener) -> StartTlsListener {
        StartTlsListener(lsnr)
    }

    pub fn bind(addr: &SocketAddr) -> io::Result<StartTlsListener> {
        Ok(StartTlsListener::new(try!(TcpListener::bind(addr))))
    }

    pub fn accept(&self) -> io::Result<Option<(StartTlsStream, SocketAddr)>> {
        self.0.accept().map(
            |res| res.map(|(stream, addr)|
                (StartTlsStream::new(stream), addr)))
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
        self.0.register(selector, token, interest, opts)
    }

    fn reregister(&self, selector: &mut mio::Selector, token: mio::Token,
                  interest: mio::EventSet, opts: mio::PollOpt)
                  -> io::Result<()> {
        self.0.reregister(selector, token, interest, opts)
    }

    fn deregister(&self, selector: &mut mio::Selector) -> io::Result<()> {
        self.0.deregister(selector)
    }
}


/// A TcpStream for stream that can start TLS later.
///
pub struct StartTlsStream(MaybeSslStream<TcpStream>);

impl StartTlsStream {
    fn new(stream: TcpStream) -> StartTlsStream {
        StartTlsStream(MaybeSslStream::Normal(stream))
    }

    pub fn wrap_client(self, ctx: &SslContext) -> Result<Self, SslError> {
        self.wrap(|s| { SslStream::connect(ctx, s) })
    }

    pub fn wrap_server(self, ctx: &SslContext) -> Result<Self, SslError> {
        self.wrap(|s| { SslStream::accept(ctx, s) })
    }

    fn wrap<F>(self, f: F) -> Result<Self, SslError>
            where F: Fn(TcpStream)
                              -> Result<SslStream<TcpStream>, SslError> {
        let stream = match self.0 {
            MaybeSslStream::Ssl(_) => { return Ok(self) }
            MaybeSslStream::Normal(s) => s
        };
        let ssl_stream = try!(f(stream));
        Ok(StartTlsStream(MaybeSslStream::Ssl(ssl_stream)))
    }

    fn tcp_stream<'a>(&'a self) -> &'a TcpStream {
        match self.0 {
            MaybeSslStream::Normal(ref s) => s,
            MaybeSslStream::Ssl(ref s) => s.get_ref(),
        }
    }

    pub fn peer_certificate(&self) -> Option<X509> {
        match self.0 {
            MaybeSslStream::Normal(_) => None,
            MaybeSslStream::Ssl(ref s) => s.ssl().peer_certificate()
        }
    }

    pub fn is_wrapped(&self) -> bool {
        match self.0 {
            MaybeSslStream::Normal(..) => false,
            MaybeSslStream::Ssl(..) => true,
        }
    }
}

impl Read for StartTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for StartTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
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

