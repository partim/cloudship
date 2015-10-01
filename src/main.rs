extern crate cloudship;
extern crate docopt;

use cloudship::droplets::webdav;
use cloudship::types::{Config, Storage};
use docopt::Docopt;
use std::env;
use std::path::Path;

static USAGE: &'static str = "
Usage: cloudship [--init] <path>

Options:
    --init  Initialize a new cloudship.
";

fn main() {
    let args = Docopt::new(USAGE)
        .and_then(|d| d.argv(env::args().into_iter()).parse())
        .unwrap_or_else(|e| e.exit());

    webdav::start();
}
