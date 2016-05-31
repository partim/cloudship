//! Parsing and scribbling of data defined through ABNF

pub mod core;
pub mod imap4;
pub mod ipaddr;

use nom;
use std::result;

pub type IResult<'a, T> = nom::IResult<&'a [u8], T>;
pub type Result<T> = result::Result<T, nom::ErrorKind>;
