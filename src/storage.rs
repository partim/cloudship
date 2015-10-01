use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

pub struct Config<'a> {
    pub http_port: u16,
    pub storage: Storage<'a>,
}

impl<'a> Config<'a> {
    pub fn new(http_port: u16, storage: Storage<'a>) -> Config<'a> {
        Config { http_port: http_port, storage: storage }
    }
}

pub struct Storage<'a> {
    pub path: &'a Path,
}

impl<'a> Storage<'a> {
    fn expand(&self, path: &Path) -> PathBuf {
        self.path.join(path)
    }

    pub fn new(path: &Path) -> Storage {
        Storage { path: path }
    }

    pub fn exists(&self, path: &Path) -> bool {
        fs::metadata(self.path).is_ok()
    }

    pub fn has_parent(&self, path: &Path) -> bool {
        self.expand(path)
            .as_path()
            .parent()
            .map_or(false, |p| fs::metadata(p).is_ok())
    }

    pub fn create_collection(&self, path: &Path) -> bool {
        fs::create_dir(self.expand(path).as_path()).is_ok()
    }
}

pub fn is_initialized(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(ref entry) => entry.is_dir(),
        _ => false,
    }
}

pub fn initialize(conf: &Config) {
    let path_str = &conf.storage.path.to_string_lossy();
    print!("Initializing storage in {}... ", path_str);

    match fs::metadata(Path::new(&conf.storage.path)) {
        Ok(ref entry) if entry.is_dir() => create_directories(conf),
        Ok(_)  => goodbye(1, &format!("{} is not a directory.", path_str)),
        Err(_) => goodbye(1, &format!("{} does not exist or is not readable.",
                                      path_str)),
    };
    println!("OK");
}

fn create_directories(conf: &Config) {
    for dir in vec!["etc", "data"] {
        let path = conf.storage.path.join(Path::new(dir));

        if fs::metadata(&path).is_ok() {
            continue;
        }

        if let Err(e) = fs::create_dir(&path) {
            goodbye(1, &format!("failed to create {} ({})",
                                path.to_string_lossy(), e));
        }
    }
}

fn goodbye(rc: i32, message: &str) {
    writeln!(io::stderr(), "FAIL: {}", message).unwrap();
    process::exit(rc);
}
