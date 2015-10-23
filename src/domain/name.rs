//! Domain names.

use std::ascii::AsciiExt;
use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;
use std::string::ToString;

use super::error::{Error, Result};

/// A single component of a domain name.
///
/// Labels are a sequence of octets, at most 63 octets in length.
///
struct DomainLabel(Vec<u8>);

impl DomainLabel {
    fn new() -> DomainLabel {
        DomainLabel(Vec::new())
    }
}

impl<'a> From<&'a [u8]> for DomainLabel {
    fn from(s: &[u8]) -> DomainLabel {
        DomainLabel(Vec::from(s))
    }
}

impl PartialEq for DomainLabel {
    fn eq(&self, other: &DomainLabel) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl fmt::Debug for DomainLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DomainLabel(\""));
        for ch in self.0.iter() {
            if ch.is_ascii() {
                try!(write!(f, "{}", *ch as char));
            }
            else {
                try!(write!(f, "{:03}", ch));
            }
        }
        write!(f, "\")")
    }
}


/// A domain name as a sequence of labels.
#[derive(Debug, PartialEq)]
pub struct DomainName(Vec<DomainLabel>);

impl DomainName {
    fn new() -> DomainName {
        DomainName(Vec::new())
    }
}

impl<'a> FromIterator<&'a [u8]> for DomainName {
    fn from_iter<T: IntoIterator<Item=&'a [u8]>>(iterator: T) -> Self {
        let mut res = DomainName::new();
        for item in iterator {
            res.0.push(DomainLabel::from(item));
        }
        res
    }
}

impl FromStr for DomainName {
    type Err = Error;

    fn from_str(s: &str) -> Result<DomainName> {
        let mut res = DomainName::new();
        res.0.push(DomainLabel::new());
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '.' => {
                            res.0.push(DomainLabel::new());
                        },
                        '\\' => {
                            let ch = try!(chars.next()
                                          .ok_or(Error::InvalidDomainName));
                            if ch.is_digit(10) {
                                let v = ch.to_digit(10).unwrap() * 100
                                      + try!(chars.next()
                                             .ok_or(Error::InvalidDomainName)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                    Error::InvalidDomainName)))
                                        * 10
                                      + try!(chars.next()
                                             .ok_or(Error::InvalidDomainName)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                  Error::InvalidDomainName)));
                                res.0.last_mut().unwrap().0.push(v as u8);
                            }
                            else {
                                res.0.last_mut().unwrap().0.push(ch as u8);
                            }
                        },
                        ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                            res.0.last_mut().unwrap().0.push(c as u8)
                        },
                        _ => return Err(Error::InvalidDomainName)
                    }
                },
                None => break
            }
        }
        Ok(res)
    }
}

impl ToString for DomainName {
    fn to_string(&self) -> String {
        let mut res = String::new();
        for item in self.0.iter() {
            if !res.is_empty() {
                res.push('.');
            }
            for u in item.0.iter() {
                match *u {
                    0x2E => res.push_str("\\."),
                    0x5C => res.push_str("\\\\"),
                    u @ _ => {
                        if u.is_ascii() && u >= 0x20 {
                            res.push(u as char)
                        }
                        else {
                            res.push('\\');
                            res.push((u / 100 + 0x30) as char);
                            res.push((u / 10 % 10 + 0x30) as char);
                            res.push((u % 10 + 0x30) as char);
                        }
                    }
                }
            }
        }
        res
    }
}


#[cfg(test)]
mod test {
    use super::DomainName;
    use std::iter::FromIterator;
    use std::str::FromStr;

    fn name_str(s: &str) -> DomainName {
        DomainName::from_str(s).unwrap()
    }

    fn name_parts(parts: Vec<&str>) -> DomainName {
        DomainName::from_iter(parts.iter().map(|p| p.as_bytes()))
    }

    fn str_ping_pong(s: &str) {
        assert_eq!(name_str(s).to_string(), s);
    }

    #[test]
    fn from_str_absolute_and_case() {
        assert_eq!(name_str("test.example.com."),
                   name_parts(vec!("test", "EXAMPLE", "com", "")));
    }

    #[test]
    fn from_str_relative() {
        assert_eq!(name_str("test.example.com"),
                   name_parts(vec!("test", "example", "com")));

    }

    #[test]
    fn from_str_escapes() {
        assert_eq!(name_str(r"tes\t.e\120ample.com\.com."),
                   name_parts(vec!("test", "example", "com.com", "")));

    }

    #[test]
    fn to_string() {
        str_ping_pong("test.example.com.");
        str_ping_pong("test.example.com");
        str_ping_pong(r"test\.e\010ample.com.");
    }
}
