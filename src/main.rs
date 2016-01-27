extern crate cloudship;
extern crate docopt;
extern crate env_logger;
extern crate openssl;

use openssl::{ssl, x509};

/*
use docopt::Docopt;
use std::env;
use std::path::Path;

static USAGE: &'static str = "
Usage: cloudship <config>
";
*/

fn main() {
    env_logger::init().unwrap();

    /*
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(env::args().into_iter()).parse())
        .unwrap_or_else(|e| e.exit());

    let config_path = Path::new(args.get_str("<config>"));

    println!("Using config file {:?}.", config_path);
    */

    let handler = cloudship::smtp::daemon::null::NullServer;
    let mut ctx = ssl::SslContext::new(ssl::SslMethod::Tlsv1).unwrap();
    ctx.set_cipher_list("DEFAULT").unwrap();
    ctx.set_certificate_file("certs/dummy.crt",
                             x509::X509FileType::PEM).unwrap();
    ctx.set_private_key_file("certs/dummy.key",
                             x509::X509FileType::PEM).unwrap();
    cloudship::smtp::Server::new("127.0.0.1:8025".parse().unwrap(), ctx)
                            .run(handler).unwrap();
}
