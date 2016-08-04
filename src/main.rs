extern crate cloudship;
extern crate env_logger;
extern crate netmachines;
extern crate openssl;
extern crate rotor;

use openssl::{ssl, x509};
use netmachines::sockets::openssl::StartTlsListener;
use cloudship::smtp;

//------------ main ---------------------------------------------------------
fn main() {
    env_logger::init().unwrap();

    let mut l = Loop::new(&rotor::Config::new()).unwrap();
    add_smtp_server(&mut l);
    l.run(()).unwrap();
}


//------------ Types used by rotor -------------------------------------------

type Machine = smtp::server::Server<(), smtp::server::NullProtocol>;
type Loop = rotor::Loop<Machine>;


//------------ SMTP Server --------------------------------------------------

fn add_smtp_server(l: &mut Loop) {
    let config = smtp::server::Config::new(create_ssl_context(),
                                           Vec::from(&b"localhost.local"[..]),
                                           Vec::from(&b"Cloudship"[..]),
                                           10485760u64);
    let lsnr = StartTlsListener::bind(&"127.0.0.1:8025".parse().unwrap(),
                                      config.ssl_context().clone()).unwrap();
    l.add_machine_with(|scope| {
        smtp::server::Server::new(lsnr, config, smtp::server::NullProtocol,
                                  scope).0
    }).unwrap()
}


//------------ Santa’s Helpers -----------------------------------------------

fn create_ssl_context() -> ssl::SslContext {
    use openssl::crypto::hash::Type;

    let mut ctx = ssl::SslContext::new(ssl::SslMethod::Tlsv1).unwrap();
    ctx.set_cipher_list("DEFAULT").unwrap();

    let gen = x509::X509Generator::new()
              .set_bitlength(2048)
              .set_valid_period(5)
              .add_name("CN".to_string(), "localhost.local".to_string())
              .set_sign_hash(Type::SHA256);
    let (cert, pkey) = gen.generate().unwrap();

    ctx.set_certificate(&cert).unwrap();
    ctx.set_private_key(&pkey).unwrap();
    ctx
}

