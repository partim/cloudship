//! Telnet-like SMTP client with STARTTSL support.
extern crate openssl;

use std::ascii::AsciiExt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use openssl::ssl;

type Stream = ssl::MaybeSslStream<TcpStream>;

fn read(stream: &mut Stream) -> io::Result<bool> {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => { return Ok(false); }
            Ok(n) => {
                print!("{}", String::from_utf8_lossy(&buf[..n]));
                if n < 4096 { return Ok(true); }
            }
            Err(e) => { return Err(e); }
        }
    }
}

fn input() -> io::Result<String> {
    let mut buf = String::new();
    try!(io::stdin().read_line(&mut buf));
    if !buf.ends_with("\r\n") {
        let _ = buf.pop();
        buf.push_str("\r\n");
    }
    Ok(buf)
}

fn write(stream: &mut Stream, buf: &String) -> io::Result<()> {
    try!(stream.write(buf.as_bytes()));
    Ok(())
}

fn run() -> io::Result<()> {
    let mut context = ssl::SslContext::new(ssl::SslMethod::Tlsv1).unwrap();
    context.set_cipher_list("DEFAULT").unwrap();
    let addr_str = "127.0.0.1:8025";
    let stream = try!(TcpStream::connect(addr_str));
    let mut stream = ssl::MaybeSslStream::Normal(stream);
    let mut starttls = false;
    loop {
        if !try!(read(&mut stream)) { return Ok(()) };
        if starttls {
            match stream {
                ssl::MaybeSslStream::Normal(s) => {
                    let s = match ssl::SslStream::connect(&context, s) {
                        Ok(s) => s,
                        Err(e) => { return Err(io::Error::new(
                                        io::ErrorKind::ConnectionAborted, e)) }
                    };
                    stream = ssl::MaybeSslStream::Ssl(s);
                },
                _ => { }
            }
            starttls = false;
        }
        let buf = try!(input());
        try!(write(&mut stream, &buf));
        if "STARTTLS\r\n".eq_ignore_ascii_case(&buf) {
            starttls = true;
        }
    }
}

fn main() {
    match run() {
        Ok(_) => { println!("Done."); }
        Err(e) => { println!("Fatal error: {}", e); }
    }
}

