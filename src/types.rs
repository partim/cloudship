use std::path::Path;

pub struct Storage {
    pub path: &'static Path,
}

pub struct Config {
    pub http_port: u16,
    pub storage: &'static Storage,
}

impl Config {
    pub fn new(http_port: u16, storage: &'static Storage) -> Config {
        Config { http_port: http_port, storage: storage }
    }
}
