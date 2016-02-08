extern crate cloudship;
extern crate env_logger;
extern crate openssl;
extern crate rotor;

use openssl::{ssl, x509};
use cloudship::smtp;

//------------ main ---------------------------------------------------------
fn main() {
    env_logger::init().unwrap();

    let event_loop = rotor::Loop::new(&rotor::Config::new()).unwrap();
    let mut loop_inst = event_loop.instantiate(Context::new());
    loop_inst.add_machine_with(|scope|
        Ok(SmtpServer::bind(&"127.0.0.1:8025".parse().unwrap(), scope)
                       .unwrap())
    ).unwrap();
    loop_inst.run().unwrap();
}

//------------ Our Server ---------------------------------------------------

type SmtpServer = smtp::Server<smtp::NullProtocol<Context>>;

//------------ Context ------------------------------------------------------

/// Composite Context that implements all the various Context traits for
/// all the various server implementations.
///
struct Context {
    ssl_context: ssl::SslContext,
}

impl Context {
    fn new() -> Context {
        Context { ssl_context: Context::create_ssl_context() }
    }

    fn create_ssl_context() -> ssl::SslContext {
        let mut ctx = ssl::SslContext::new(ssl::SslMethod::Tlsv1).unwrap();
        ctx.set_cipher_list("DEFAULT").unwrap();
        ctx.set_certificate_file("certs/dummy.crt",
                                 x509::X509FileType::PEM).unwrap();
        ctx.set_private_key_file("certs/dummy.key",
                                 x509::X509FileType::PEM).unwrap();
        ctx
    }

}

impl cloudship::smtp::server::Context for Context {
    fn ssl_context(&self) -> ssl::SslContext { self.ssl_context.clone() }
    fn hostname(&self) -> &[u8] { b"localhost.local" }
    fn systemname(&self) -> &[u8] { b"Cloudship" }
    fn message_size_limit(&self) -> u64 { 10485760u64 }
}

