use nom;
use std::collections::HashSet;
use std::fmt;
use ::util::abnf::core::{cat_chrs, chr};
use ::util::abnf::imap4::{test_atom_char};
use ::util::abnf::{IResult, Result};

// settings, kind of

#[derive(Debug)]
pub enum Charset {
    Utf8
}

#[derive(Debug)]
pub enum Capability {
    Imap4Rev1
}

// fundamental types

#[derive(Debug)]
pub enum Wildcard {
    Anything,
    Segment
}

impl fmt::Display for Wildcard {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Wildcard::Anything => write!(f, "*"),
            Wildcard::Segment  => write!(f, "%")
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Tag<'a> {
    Tagged(&'a [u8]),
    Untagged
}

// tag             = 1*<any ASTRING-CHAR except "+">
// ASTRING-CHAR   = ATOM-CHAR / resp-specials
// ATOM-CHAR       = <any CHAR except atom-specials>
// atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
//                  quoted-specials / resp-specials
// quoted-specials = DQUOTE / "\"
// resp-specials   = "]"
// list-wildcards  = "%" / "*"

impl<'a> Tag<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<Tag<'a>> {
        alt!(input,
             map!(call!(chr, b'*'), |_| Tag::Untagged) |
             map!(call!(cat_chrs, Tag::test_tag), |a| Tag::Tagged(a)))
    }

    fn test_tag(chr: u8) -> Result<u8> {
        if chr != b'+' && test_atom_char(chr).is_ok() { Ok(chr ) }
        else { Err(nom::ErrorKind::Char) }
    }
}

#[derive(Debug)]
pub struct Notice<'a>(&'a[u8]);

#[derive(Debug, Eq, PartialEq)]
pub struct UidValue(u32);

#[derive(Debug, Eq, PartialEq)]
pub struct UidValidity(u32);

#[derive(Debug, Eq, PartialEq)]
pub struct Uid {
    value: UidValue,
    validity: UidValidity
}

#[derive(Debug)]
pub struct MessageNumber(u32);

// message related types?

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Flag<'a> {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    Recent,
    Flexible(&'a[u8])
}

#[derive(Debug)]
pub struct Flags<'a>(HashSet<Flag<'a>>);

#[derive(Debug)]
pub enum MessageAttribute<'a> {
    UniqueIdentifier,
    SequenceNumber,
    Flags(HashSet<Flag<'a>>),
    InternalDate,
    Size(u32),
    EnvelopeStructure,
    BodyStructure
}

//------------ Commands -----------------------------------------------------

/// IMAP Commands
///
#[derive(Debug)]
pub enum Command {
    // RFC 3501
    Noop
}

impl Command {
    pub fn parse<'a>(input: &'a [u8]) -> IResult<Command> {
        unimplemented!()
    }
}


//------------ Responses ----------------------------------------------------

/// IMAP Responses
///
#[derive(Debug)]
pub enum Response<'a> {
    // RFC 3501
    Ok(Option<Tag<'a>>, ResponseCode<'a>, Notice<'a>)
}

impl<'a> fmt::Display for Response<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unimplemented!()
    }
}

/// IMAP Response codes
///
#[derive(Debug)]
pub enum ResponseCode<'a> {
    Alert(Notice<'a>),
    BadCharset(Vec<Charset>),
    Capability(Vec<Capability>),
    Parse(Notice<'a>),
    PermanentFlags(Flags<'a>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidValidity(Uid),
    Unseen(MessageNumber)
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use nom::IResult::Done;
    use super::*;

    #[test]
    fn test_format() {
        assert_eq!(format!("{}", Tag::Tagged(b"a01")), "a01");
        assert_eq!(format!("{}", Tag::Untagged), "*");
        assert_eq!(format!("{}", Wildcard::Segment), "%");
    }

    #[test]
    fn test_parse() {
        assert_eq!(Tag::parse(b"*"),
                   Done(&b""[..], Tag::Untagged));
        assert_eq!(Tag::parse(b"a001"),
                   Done(&b""[..], Tag::Tagged(b"a001")));
    }
}
