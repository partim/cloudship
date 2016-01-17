//! Core Rules
//!
//! These are defined in RFC 5234, appendix B.1.
//!

use nom::{self, Err, ErrorKind, Needed};
use nom::IResult::{Error, Done, Incomplete};
use super::{IResult, Result};


//------------ Test and Translation Functions -------------------------------

/// Test for ALPHA
///
/// > ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z
///
pub fn test_alpha(chr: u8) -> Result<u8> {
    if nom::is_alphabetic(chr) { Ok(chr) }
    else { Err(ErrorKind::Alpha) }
}


/// Test for `ALPHA / DIGIT`.
///
pub fn test_alpha_digit(chr: u8) -> Result<u8> {
    if nom::is_alphanumeric(chr) { Ok(chr) }
    else { Err(ErrorKind::AlphaNumeric) }
}


/// Test for and translate BIT
///
/// > BIT            =  "0" / "1"
///
pub fn test_bit(chr: u8) -> Result<bool> {
    match chr {
        b'0' => Ok(false),
        b'1' => Ok(true),
        _ => Err(ErrorKind::Digit)
    }
}


/// Tests CHAR
///
/// > CHAR           =  %x01-7F
///
pub fn test_char(chr: u8) -> Result<u8> {
    if chr >= 1 && chr <= 0x7f { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Tests for CR
///
/// > CR             =  %x0D
/// >                        ; carriage return
pub fn test_cr(chr: u8) -> Result<u8> {
    if chr == b'\r' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Test for CTL
///
/// > CTL            =  %x00-1F / %x7F
/// >                        ; controls
///
pub fn test_ctl(chr: u8) -> Result<u8> {
    if chr <= 0x1F || chr == 0x7F { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Test for and translate DIGIT
///
/// > DIGIT          =  %x30-39
/// >                        ; 0-9
///
pub fn test_digit(chr: u8) -> Result<u8> {
    match chr {
        b'0' ... b'9' => Ok(chr - b'0'),
        _ => Err(ErrorKind::Digit)
    }
}


/// Test for DQUOTE
///
/// > DQUOTE         =  %x22
/// >                        ; " (Double Quote)
pub fn test_dquote(chr: u8) -> Result<u8> {
    if chr == b'"' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Test for HEXDIG
///
pub fn test_hexdig(chr: u8) -> Result<u8> {
    match chr {
        b'0' ... b'9' => Ok(chr - b'0'),
        b'A' ... b'F' => Ok(chr - b'A' + 0xA),
        b'a' ... b'f' => Ok(chr - b'a' + 0xA),
        _ => Err(ErrorKind::Digit)
    }
}


/// Tests for HTAB
///
pub fn test_htab(chr: u8) -> Result<u8> {
    if chr == b'\t' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Tests for LF
///
pub fn test_lf(chr: u8) -> Result<u8> {
    if chr == b'\n' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Tests for SP
///
pub fn test_sp(chr: u8) -> Result<u8> {
    if chr == b' ' { Ok(chr) }
    else { Err(ErrorKind::Space) }
}


/// Tests for a VCHAR
///
pub fn test_vchar(chr: u8) -> Result<u8> {
    if chr >= 0x21 && chr <= 0x7E { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


/// Test for a WSP
///
pub fn test_wsp(chr: u8) -> Result<u8> {
    if chr == b' ' || chr == b'\t' { Ok(chr) }
    else { Err(ErrorKind::Space) }
}


//------------ Parser Functions ----------------------------------------------

/// Parses ALPHA
///
/// > ALPHA          =  %x41-5A / %x61-7A   ; A-Z / a-z
///
pub fn alpha(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_alpha)
}

/// Parses 1*ALPHA
///
pub fn alphas(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_alpha)
}


/// Parses `ALPHA / DIGIT`
///
pub fn alpha_digit(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_alpha_digit)
}

/// Parses `ALPHA / DIGIT`
///
pub fn alpha_digits(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_alpha_digit)
}


/// Pares BIT
///
/// > BIT            =  "0" / "1"
///
pub fn bit(input: &[u8]) -> IResult<bool> {
    cat_chr(input, test_bit)
}


/// Parses CHAR
///
/// > CHAR           =  %x01-7F
///
pub fn char(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_char)
}

/// Parses 1*CHAR
///
pub fn chars(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_char)
}


/// Parses CR
///
/// > CR             =  %x0D
///
pub fn cr(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_cr)
}


/// Parses CRLF
///
/// > CRLF           =  CR LF
/// >                        ; Internet standard newline
///
named!(pub crlf, tag_bytes!(b"\r\n"));


/// Parses CTL
///
/// > CTL            =  %x00-1F / %x7F
/// >                        ; controls
///
pub fn ctl(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_ctl)
}

/// Parses 1*CTL
///
pub fn ctls(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_ctl)
}


/// Parses DIGIT into its value
///
pub fn digit(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_digit)
}

/// Parses 1*DIGIT
///
pub fn digits(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_digit)
}

/// Parses 1*3DIGIT for an `u8`, ie., "0" up to "255".
///
pub fn u8_digits(mut input: &[u8]) -> IResult<u8> {
    let mut res = [0u8, 0, 0];
    for i in 0..3 {
        match digit(input) {
            Incomplete(n) => { return Incomplete(n) },
            Done(rest, chr) => {
                input = rest;
                res[i] = chr;
            }
            Error(e) => {
                match i {
                    0 => return Error(e),
                    1 => return Done(input, res[0]),
                    2 => return Done(input, res[0] * 10 + res[1]),
                    _ => unreachable!()
                }
            }
        }
    }
    match (res[0], res[1], res[2]) {
        (0...1, _, _) | (2, 0...4, _) | (2, 5, 0...5) =>  {
            Done(input, res[0] * 100 + res[1] * 10 + res[2])
        }
        _ => Error(Err::Position(ErrorKind::OneOf, input))
    }
}

/// Parses 1*20DIGIT for an `u64`.
///
pub fn u64_digits(input: &[u8]) -> IResult<u64> {
    use std::str::from_utf8_unchecked;

    let (output, res) = try_parse!(input, call!(nm_cat_chrs, 1, 20,
                                                test_digit));
    let res = unsafe { from_utf8_unchecked(res) };
    match u64::from_str_radix(res, 10) {
        Ok(res) => { Done(output, res) }
        Err(_) => { Error(Err::Position(ErrorKind::Digit, input)) }
    }
}

/// Parses DQUOTE
///
pub fn dquote(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_dquote)
} 


/// Parses a HEXDIG
///
pub fn hexdig(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_hexdig)
}

/// Parses 1*HEXDIG
///
pub fn hexdigs(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_hexdig)
}

/// Parses 1*2HEXDIG into a `u8`
///
pub fn u8_hexdigs(input: &[u8]) -> IResult<u8> {
    let (input, res) = try_parse!(input, hexdig);
    match hexdig(input) {
        Incomplete(n) => Incomplete(n),
        Error(_) => Done(input, res),
        Done(rest, v) => Done(rest, (res << 4) | v)
    }
}
        
/// Parses 1*4HEXDIG into a `u16`
///
pub fn u16_hexdigs(mut input: &[u8]) -> IResult<u16> {
    let mut res = 0u16;
    for i in 0..4 {
        match hexdig(input) {
            Incomplete(n) => return Incomplete(n),
            Error(e) => {
                if i == 0 { return Error(e) }
                else { return Done(input, res) }
            },
            Done(rest, v) => {
                input = rest;
                res = (res << 4) | (v as u16);
            }
        }
    }
    Done(input, res)
}

/// Parses 1*8HEXDIG into a `u32`
///
pub fn u32_hexdig(mut input: &[u8]) -> IResult<u32> {
    let mut res = 0u32;
    for i in 0..8 {
        match hexdig(input) {
            Incomplete(n) => return Incomplete(n),
            Error(e) => {
                if i == 0 { return Error(e) }
                else { return Done(input, res) }
            },
            Done(rest, v) => {
                input = rest;
                res = (res << 4) | (v as u32);
            }
        }
    }
    Done(input, res)
}


/// Parses a HTAB
///
pub fn htab(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_htab)
}


/// Parses an LF
///
pub fn lf(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_lf)
}


// LWSP: use discouraged by RFC 5234
// OCTET: silly to have

/// Parses an SP
///
pub fn sp(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_sp)
}


/// Parses a VCHAR
///
pub fn vchar(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_vchar)
}


/// Parses a WSP
///
pub fn wsp(input: &[u8]) -> IResult<u8> {
    cat_chr(input, test_wsp)
}


/// Parses 1*WSP
///
pub fn wsps(input: &[u8]) -> IResult<&[u8]> {
    cat_chrs(input, test_wsp)
}

/// Pares *WSP
///
pub fn opt_wsps(input: &[u8]) -> IResult<&[u8]> {
    opt_cat_chrs(input, test_wsp)
}


/// Parses `*WSP CRLF` into nothing.
///
pub fn wspcrlf(input: &[u8]) -> IResult<()> {
    let (wsout, _) = try_parse!(input, opt_wsps);
    let (crlfout, _) = try_parse!(wsout, crlf);
    Done(crlfout, ())
}


/// Parses an ABNF text string, ie., the given text in a case-insensitive
/// manner.
///
pub fn text<'a, 'b>(input: &'a[u8], text: &'b[u8])
                    -> nom::IResult<&'a[u8], &'a[u8]> {
    use std::cmp::min;
    use std::ascii::AsciiExt;
    let len = input.len();
    let textlen = text.len();
    let minlen = min(len, textlen);
    let reduced = &input[..minlen];
    let textreduced = &text[..minlen];

    if !reduced.eq_ignore_ascii_case(textreduced) {
        Error(Err::Position(ErrorKind::Tag, input))
    }
    else if minlen < textlen {
        Incomplete(Needed::Size(textlen))
    }
    else {
        Done(&input[textlen..], reduced)
    }
}


//------------ Generic Functions --------------------------------------------

pub fn chr(input: &[u8], chr: u8) -> IResult<u8> {
    cat_chr(input, |c| if c == chr { Ok(c) } else { Err(ErrorKind::Char) })
}

pub fn cat_chr<F, T>(input: &[u8], f: F) -> IResult<T>
               where F: Fn(u8) -> Result<T> {
    if input.len() < 1 {
        nom::IResult::Incomplete(Needed::Size(1))
    }
    else {
        match f(input[0]) {
            Ok(res) => nom::IResult::Done(&input[1..], res),
            Err(kind) => nom::IResult::Error(Err::Position(kind, input))
        }
    }
}

pub fn cat_chrs<F, T>(input: &[u8], f: F) -> IResult<&[u8]>
               where F: Fn(u8) -> Result<T> {
    for (idx, item) in input.iter().enumerate() {
        match f(*item) {
            Ok(_) => { },
            Err(kind) => {
                if idx == 0 {
                    return Error(Err::Position(kind, input))
                }
                else {
                    return Done(&input[idx..], &input[0..idx])
                }
            }
        }
    }
    Done(b"", input)
}

pub fn opt_cat_chrs<F, T>(input: &[u8], f: F) -> IResult<&[u8]>
                   where F: Fn(u8) -> Result<T> {
    for (idx, item) in input.iter().enumerate() {
        match f(*item) {
            Ok(_) => { },
            Err(_) => {
                return Done(&input[idx..], &input[0..idx])
            }
        }
    }
    Done(b"", input)
}

pub fn nm_cat_chrs<F, T>(input: &[u8], n: usize, m: usize, f: F)
                         -> IResult<&[u8]>
                   where F: Fn(u8) -> Result<T> {
    for (idx, item) in input.iter().enumerate() {
        match f(*item) {
            Ok(_) => {
                if idx == m {
                    return Done(&input[idx..], &input[0..idx])
                }
            }
            Err(kind) => {
                if idx < n {
                    return Error(Err::Position(kind, input))
                }
                else {
                    return Done(&input[idx..], &input[0..idx])
                }
            }
        }
    }
    Incomplete(Needed::Size(input.len() - n))
}
