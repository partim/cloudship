//! IMAP4 rules
//!
//! These are defined in RFC 3501, appendix 9.
//!

use nom::ErrorKind;
use super::Result;
use super::core::{test_char, test_dquote, test_ctl, test_sp};


//------------ Test and Translation Functions -------------------------------

/// Test for and translate ATOM-CHAR.
///
/// > ATOM-CHAR       =  <any CHAR except atom-specials>
///
pub fn test_atom_char(chr: u8) -> Result<u8> {
    if test_char(chr).is_ok() && !test_atom_special(chr).is_ok() { Ok(chr) }
    else { Err(ErrorKind::Char) }
}

/// Test for and translate atom-specials.
///
/// > atom-specials   =   "(" / ")" / "{" / SP / CTL / list-wildcards /
///                       quoted-specials / resp-specials
///
fn test_atom_special(chr: u8) -> Result<u8> {
    // Use one_of!()
    if chr == b'(' || chr == b')' || chr == b'{'
        || test_sp(chr).is_ok()
        || test_ctl(chr).is_ok()
        || test_wildcard(chr).is_ok()
        || test_quoted_special(chr).is_ok()
        || test_resp_special(chr).is_ok() {
            Ok(chr)
        } else {
            Err(ErrorKind::Char)
        }
}

/// Test for and translate wildcards.
///
/// > list-wildcards  =   "%" / "*"
///
fn test_wildcard(chr: u8) -> Result<u8> {
    if chr == b'%' || chr == b'*' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}

/// Test for and translate quoted specials.
///
/// > quoted-specials  = DQUOTE / "\"
///
fn test_quoted_special(chr: u8) -> Result<u8> {
    if test_dquote(chr).is_ok() || chr == b'\\' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}

/// Test for and translate response specials.
///
/// > resp-specials    = "]"
///
fn test_resp_special(chr: u8) -> Result<u8> {
    if chr == b']' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}
