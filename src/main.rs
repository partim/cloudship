extern crate cloudship;
extern crate docopt;
extern crate env_logger;

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

    cloudship::smtp::Daemon::new(&"127.0.0.1:8025".parse().unwrap(),
                                 b"localhost.local").run().unwrap();
}
