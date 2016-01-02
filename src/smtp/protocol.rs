
/// SMTP Commands
///
#[derive(Debug)]
pub enum Command<'a> {
    // RFC 5321
    Ehlo { domain: &'a [u8] },
    Helo { domain: &'a [u8] },
    Mail { reverse_path: &'a [u8], params: () },
    Rcpt { path: &'a[u8], params: () },
    Data,
    Rset,
    Vrfy { whom: &'a [u8], smtputf8: Option<()> },
    Expn { whom: &'a [u8], smtputf8: Option<()> },
    Help { what: Option<&'a [u8]> },
    Noop { what: Option<&'a [u8]> },
    Quit,

    // RFC 3030
    Bdat { size: usize, last: bool },

    // RFC 3207
    StartTls,

    // RFC 4954
    Auth { mechanism: &'a [u8], initial: Option<&'a [u8]> },
}

pub struct MailParameters<'a> {
    pub body: Option<BodyValue>,
    pub size: Option<usize>,
    pub ret: Option<RetValue>,
    pub envid: Option<&'a [u8]>,
    pub auth: Option<&'a [u8]>,
    pub smtputf8: Option<()>,
}

pub struct RcptParameters<'a> {
    pub notify: Option<NotifyValue>,
    pub orcpt: Option<OrcptParameter<'a>>,
}

/// The BODY parameter to the ESMTP MAIL command
///
/// See RFC 6152, section 2, and RFC 3030, section 3.
///
pub enum BodyValue {
    SevenBit,
    EightBitMime,
    BinaryMime,
}

/// The NOTIFY parameter of the ESMTP RCPT command
///
/// See RFC 3461, section 4.1.
///
pub struct NotifyValue {
    pub succuss: bool,
    pub failure: bool,
    pub delay: bool
}

/// The Orcpt parameter to the ESMTP RCPT command
///
/// See RFC 3461, section 4.2.
///
pub struct OrcptParameter<'a> {
    pub addr_type: AddressType,
    pub addr: &'a[u8],
}

/// The RET parameter of the ESMTP MAIL command
///
/// See RFC 3461, section 4.3.
///
pub enum RetValue {
    Full,
    Hdrs,
}

/// DSN Address Types
///
/// https://www.iana.org/assignments/dsn-types/dsn-types.xhtml#dsn-types-1
///
pub enum AddressType {
    Rfc822,
    X400,
    Utf8
}

