use std::collections::HashSet;

#[derive(Debug)]
pub struct Tag<'a>(&'a[u8]);

#[derive(Debug)]
pub struct Notification<'a>(&'a[u8]);

#[derive(Debug)]
pub enum Charset {
    Utf8
}

#[derive(Debug)]
pub enum Capability {
    Imap4Rev1
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum Flag<'a> {
    Seen,
    Answered,
    Flagged,
    Deleted,
    Draft,
    Recent,
    ClientDefined(&'a[u8])
}

#[derive(Debug)]
pub struct UidVal(u32);

#[derive(Debug)]
pub struct MessageNumber(u32);


//------------ Commands -----------------------------------------------------

/// IMAP Commands
///
#[derive(Debug)]
pub enum Command {
    // RFC 3501
    Noop
}

//------------ Responses ----------------------------------------------------

/// IMAP Response codes
///
#[derive(Debug)]
pub enum ResponseCode<'a> {
    Alert(Notification<'a>),
    BadCharset(Vec<Charset>),
    Capability(Vec<Capability>),
    Parse(Notification<'a>),
    PermanentFlags(HashSet<Flag<'a>>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidValidity(UidVal),
    Unseen(MessageNumber)
}


/// IMAP Responses
///
#[derive(Debug)]
pub enum Response<'a> {
    // RFC 3501
    Ok(Tag<'a>)
}
