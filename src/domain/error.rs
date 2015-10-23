//! Error and Result of the domain module.

use std::error::Error as StdError;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::result;


pub type Result<T> = result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {

    /// a class code was invalid
    InvalidClass,

    /// a class name was invalid
    InvalidClassName,

    /// a domain name was invalid
    InvalidDomainName,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl StdError for Error {
    fn description(&self) -> &str {
        match *self {
            Error::InvalidClass => "invalid class",
            Error::InvalidClassName => "invalid class name",
            Error::InvalidDomainName => "invalid domain name",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        match *self {
            _ => None,
        }
    }
}
