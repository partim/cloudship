extern crate cloudship;
extern crate docopt;

use cloudship::droplets::webdav;
use cloudship::storage;
use cloudship::storage::{Config, Storage};
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

    let path = args.get_str("<path>");
    let store = Storage::new(Path::new(&path));
    let conf = Config::new(8080, store);

    if args.get_bool("--init") {
        storage::initialize(&conf)
    }

    webdav::start(&conf);
}
