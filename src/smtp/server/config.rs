//! Configuration for SMTP servers.

use openssl::ssl::SslContext;

pub struct Config {
    context: SslContext,
    hostname: Vec<u8>,
    systemname: Vec<u8>,
    size_limit: u64,
}

impl Config {
    pub fn new(context: SslContext, hostname: Vec<u8>, systemname: Vec<u8>,
               message_size_limit: u64) ->  Self {
        Config { context: context, hostname: hostname,
                 systemname: systemname, size_limit: message_size_limit }
    }

    pub fn ssl_context(&self) -> &SslContext {
        &self.context
    }

    pub fn hostname(&self) -> &[u8] {
        &self.hostname
    }

    pub fn systemname(&self) -> &[u8] {
        &self.systemname
    }

    pub fn message_size_limit(&self) -> u64 {
        self.size_limit
    }
}

