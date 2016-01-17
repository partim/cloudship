use std::net::{Ipv4Addr, Ipv6Addr};
use nom::{IResult, ErrorKind, is_alphanumeric};
use nom::IResult::{Done, Error, Incomplete};
use ::util::abnf::core::{alpha_digit, cat_chr, cat_chrs, chr, opt_cat_chrs,
                         opt_wsps, text, u64_digits, wspcrlf, wsps};

//------------ Macros -------------------------------------------------------

/// `empty_command!(&[T]: nom::AsBytes) =>
///                                 &[T] -> IResult<&[T], Command, CommandError>
///
/// The command $verb without parameters resulting in $result
///
macro_rules! empty_command (
    ($i:expr, $verb: expr, $result: expr) => (
        chain!($i,
            call!(text, $verb) ~ 
            res: alt!(map!(wspcrlf, |_| Ok($result) ) |
                      map!(take_until_and_consume!(b"\r\n"),
                           |_| Err(CommandError::Parameters))
                 ),
            || res
        )
    );
);

/// `command!(&[T]: nom::AsBytes) => &[T] -> IResult<&[T], ::CommandResult>
/// 
/// The command $verb with parameters and result defined through a parser.
///
macro_rules! command (
    ($i:expr, $verb: expr, $($rest:tt)*) => (
        alt!($i,
            chain!(call!(text, $verb) ~ wsps ~
                   res: $($rest)* ~ wspcrlf, || Ok(res)) |
            chain!(call!(text, $verb) ~ take_until_and_consume!(b"\r\n"),
                   || Err(CommandError::Parameters))
        )
    );
);

macro_rules! method (
    ($i:expr, $s:ident, $fun:ident) => ( $s.$fun( $i ) );
    //($i:expr, $fun:expr, $($args:expr),* ) => ( self.$fun( $i, $($args),* ) );
);


//------------ CommandError -------------------------------------------------

#[derive(Debug)]
pub enum CommandError {
    /// "Syntax error, command unrecognized" (500)
    Unrecognized,

    /// "Syntax error in parameters or arguments" (501)
    Parameters,
}


//------------ Command ------------------------------------------------------

/// SMTP Commands
///
#[derive(Debug)]
pub enum Command<'a> {
    // RFC 5321
    Ehlo(MailboxDomain<'a>), 
    Helo(Domain<'a>),
    Mail(ReversePath<'a>, MailParameters<'a>),
    Rcpt(RcptPath<'a>, RcptParameters<'a>),
    Data,
    Rset,
    Vrfy(Word<'a>, VrfyParameters),
    Expn(Word<'a>, ExpnParameters),
    Help(Option<Word<'a>>),
    Noop,
    Quit,

    // RFC 3030
    Bdat { size: u64, last: bool },

    // RFC 3207
    StartTls,

    // RFC 4954
    Auth { mechanism: &'a[u8], initial: Option<&'a[u8]> },
}

impl<'a> Command<'a> {
    pub fn parse(input: &'a [u8])
                 -> IResult<&'a [u8], Result<Command<'a>, CommandError>> {
        alt!(input,
             command!(b"EHLO", 
                      map!(call!(MailboxDomain::parse),
                           |res| Command::Ehlo(res))
             ) |
             command!(b"HELO",
                      map!(call!(Domain::parse),
                           |res| Command::Helo(res))
             ) |
             command!(b"MAIL",
                      chain!(call!(text, b"FROM:") ~
                             path: call!(ReversePath::parse) ~
                             params: call!(MailParameters::parse),
                             || Command::Mail(path, params))
             ) |
             command!(b"RCPT",
                      chain!(call!(text, b"TO:") ~
                             path: call!(RcptPath::parse) ~
                             params: call!(RcptParameters::parse),
                             || Command::Rcpt(path, params))
             ) |
             empty_command!(b"DATA", Command::Data) |
             empty_command!(b"DATA", Command::Rset) |
             command!(b"VRFY",
                      chain!(word: call!(Word::parse) ~
                             params: call!(VrfyParameters::parse),
                             || Command::Vrfy(word, params))
             ) |
             command!(b"EXPN",
                      chain!(word: call!(Word::parse) ~
                             params: call!(ExpnParameters::parse),
                             || Command::Expn(word, params))
             ) |
             command!(b"HELP",
                      map!(opt!(call!(Word::parse)), |res| Command::Help(res))
             ) |
             empty_command!(b"NOOP", Command::Noop) |
             empty_command!(b"QUIT", Command::Noop) |
             command!(b"BDAT",
                      chain!(size: call!(u64_digits) ~
                             last: opt!(chain!(wsps ~ call!(text, b"LAST"),
                                               || ())),
                             || Command::Bdat { size: size,
                                                last: last.is_some() })
             ) |
             empty_command!(b"STARTTLS", Command::StartTls) |
             command!(b"AUTH",
                      chain!(mechanism: call!(atom) ~ wsps ~
                             initial: opt!(call!(atom)),
                             || Command::Auth { mechanism: mechanism,
                                                initial: initial })
             )
        )
    }
}


//------------ MailParameters -----------------------------------------------

#[derive(Debug)]
pub struct MailParameters<'a> {
    pub body: Option<BodyValue>,
    pub size: Option<u64>,
    pub ret: Option<RetValue>,
    pub envid: Option<Xtext<'a>>,
    pub auth: Option<Mailbox<'a>>,
    pub smtputf8: Option<()>,
}

impl<'a> MailParameters<'a> {
    pub fn new() -> MailParameters<'a> {
        MailParameters { body: None, size: None, ret: None, envid: None,
                         auth: None, smtputf8: None }
    }

    pub fn parse(mut input: &'a [u8])
                 -> IResult<&'a [u8], MailParameters<'a>> {
        let mut body = None;
        let mut size = None;
        let mut ret = None;
        let mut envid = None;
        let mut auth = None;
        let mut smtputf8 = None;

        loop {
            let step = chain!(input,
                opt_wsps ~
                alt!(
                    call!(MailParameters::parse_body) => {
                        |res| { body = Some(res); () }
                    } |
                    call!(MailParameters::parse_size) => {
                        |res| { size = Some(res); () }
                    } |
                    call!(MailParameters::parse_ret) => {
                        |res| { ret = Some(res); () }
                    } |
                    call!(MailParameters::parse_envid) => {
                        |res| { envid = Some(res); () }
                    } |
                    call!(MailParameters::parse_auth) => {
                        |res| { auth = Some(res); () }
                    } |
                    call!(MailParameters::parse_smtputf8) => {
                        |_| { smtputf8 = Some(()); () }
                    }
                ),
                || ()
            );
            match step {
                Incomplete(n) => { return Incomplete(n) }
                Error(_) => { break }
                Done(rest, _) => { input = rest }
            }
        }
        Done(input, MailParameters { body: body, size: size, ret: ret,
                                     envid: envid, auth: auth,
                                     smtputf8: smtputf8 })
    }

    /// Parses the mail-parameter BODY.
    ///
    /// > body-mail-parameter = "BODY=" body-value
    /// > body-value          = "7BIT" / "8BITMIME" / "BINARYMIME"
    ///
    /// Defined in RFC 6152 and extended in RFC 3030.
    ///
    fn parse_body(input: &[u8]) -> IResult<&[u8], BodyValue> {
        chain!(input,
            call!(text, b"BODY=") ~ res: call!(BodyValue::parse),
            || res)
    }

    /// Parses the mail-parameter SIZE.
    ///
    /// > size-mail-parameter = "SIZE=" size-value
    /// > size-value          = 1*20DIGIT
    ///
    /// Defined in RFC 1870.
    ///
    fn parse_size(input: &[u8]) -> IResult<&[u8], u64> {
        chain!(input,
               call!(text, b"SIZE=") ~ res: u64_digits,
               || res
        )
    }

    /// Parses the mail-parameter RET.
    ///
    /// > ret-mail-parameter = "RET=" ret-value
    /// > ret-value          = "FULL" / "HDRS"
    ///
    /// Defined in RFC 3461, section 4.3.
    ///
    fn parse_ret(input: &[u8]) -> IResult<&[u8], RetValue> {
        chain!(input,
               call!(text, b"RET=") ~ res: call!(RetValue::parse),
               || res)
    }

    /// Parses the mail-parameter ENVID.
    ///
    /// > envid-parameter = "ENVID=" xtext
    ///
    /// Defined in RFC 3461, section 4.4.
    ///
    fn parse_envid(input: &[u8]) -> IResult<&[u8], Xtext> {
        chain!(input,
               call!(text, b"ENVID=") ~ res: call!(Xtext::parse),
               || res)
    }

    /// Parses the mail-parameter AUTH.
    ///
    /// > auth-mail-parameter = "AUTH=" Mailbox
    ///
    /// Defined in RFC 4954, section 5.
    ///
    fn parse_auth(input: &[u8]) -> IResult<&[u8], Mailbox> {
        chain!(input,
               call!(text, b"AUTH=") ~ res: call!(Mailbox::parse),
               || res)
    }

    /// Parses the mail-parameter SMTPUTF8.
    ///
    /// Defined in RFC 6531.
    ///
    fn parse_smtputf8(input: &[u8]) -> IResult<&[u8], ()> {
        let (output, _) = try_parse!(input, call!(text, b"SMTPUTF8"));
        Done(output, ())
    }

}


/// The BODY parameter to the ESMTP MAIL command
///
/// See RFC 6152, section 2, and RFC 3030, section 3.
///
#[derive(Debug)]
pub enum BodyValue {
    SevenBit,
    EightBitMime,
    BinaryMime,
}

impl BodyValue {
    pub fn parse(input: &[u8]) -> IResult<&[u8], BodyValue> {
        alt!(input,
             call!(text, b"7BIT") => { |_| BodyValue::SevenBit } |
             call!(text, b"8BITMIME") => { |_| BodyValue::EightBitMime }|
             call!(text, b"BINARYMIME") => { |_| BodyValue::BinaryMime }
        )
    }
}


/// The RET parameter of the ESMTP MAIL command
///
/// See RFC 3461, section 4.3.
///
#[derive(Debug)]
pub enum RetValue {
    Full,
    Hdrs,
}

impl RetValue {
    pub fn parse(input: &[u8]) -> IResult<&[u8], RetValue> {
        alt!(input,
             call!(text, b"FULL") => { |_| RetValue::Full } |
             call!(text, b"HDRS") => { |_| RetValue::Hdrs }
        )
    }
}


//------------ RcptPath -----------------------------------------------------

#[derive(Debug)]
pub enum RcptPath<'a> {
    DomainPostmaster(Domain<'a>),
    Postmaster,
    ForwardPath(Path<'a>),
}

impl<'a> RcptPath<'a> {
    pub fn parse(input: &'a[u8]) -> IResult<&'a[u8], RcptPath<'a>> {
        alt!(input,
             chain!(tag!(b"<Postmaster@") ~
                    domain: call!(Domain::parse) ~
                    call!(chr, b'>'),
                    || RcptPath::DomainPostmaster(domain)
             ) |
             tag!(b"<Postmaster>") => {
                 |_| RcptPath::Postmaster
             } |
             call!(Path::parse) => {
                 |res| RcptPath::ForwardPath(res)
             })
    }
}

//------------ RcptParameters -----------------------------------------------

#[derive(Debug)]
pub struct RcptParameters<'a> {
    pub notify: Option<NotifyValue>,
    pub orcpt: Option<OrcptParameter<'a>>,
}

impl<'a> RcptParameters<'a> {
    pub fn parse(mut input: &'a[u8]) -> IResult<&'a[u8], RcptParameters<'a>> {
        let mut notify = None;
        let mut orcpt = None;

        loop {
            let step = chain!(input,
                opt_wsps ~
                alt!(
                    call!(RcptParameters::parse_notify) => {
                        |res| { notify = Some(res); () }
                    } |
                    call!(RcptParameters::parse_orcpt) => {
                        |res| { orcpt = Some(res); () }
                    }
                ),
                || ()
            );
            match step {
                Incomplete(n) => { return Incomplete(n) }
                Error(_) => { break }
                Done(rest, _) => { input = rest }
            }
        }
        Done(input, RcptParameters { notify: notify, orcpt: orcpt })
    }

    /// Parses the rcpt-parameter NOTIFY.
    ///
    /// > notify-rcpt-parameter = "NOTIFY=" notify-esmtp-value
    ///
    /// Defined in RFC 3461, section 4.1.
    ///
    fn parse_notify(input: &[u8]) -> IResult<&[u8], NotifyValue> {
        chain!(input,
               call!(text, b"NOTIFY=") ~ res: call!(NotifyValue::parse),
               || res)
    }

    /// Parses the rcpt-parameter ORCPT
    ///
    /// > orcpt-parameter = "ORCPT=" original-recipient-address
    ///
    /// Defined in RFC 3461, section 4.2.
    ///
    pub fn parse_orcpt(input: &'a[u8]) -> IResult<&'a[u8],
                                                  OrcptParameter<'a>> {
        chain!(input,
               call!(text, b"ORCPT=") ~ res: call!(OrcptParameter::parse),
               || res)
    }
}


/// The NOTIFY parameter of the ESMTP RCPT command
///
/// See RFC 3461, section 4.1.
///
#[derive(Debug)]
pub struct NotifyValue {
    pub success: bool,
    pub failure: bool,
    pub delay: bool
}

impl NotifyValue {
    pub fn new() -> NotifyValue {
        NotifyValue { success: false, failure: false, delay: false }
    }

    /// > notify-esmtp-value    = "NEVER" / (notify-list-element
    /// >                                    *( "," notify-list-element))
    /// > notify-list-element   = "SUCCESS" / "FAILURE" / "DELAY"
    pub fn parse(input: &[u8]) -> IResult<&[u8], NotifyValue> {
        alt!(input,
             call!(text, b"NEVER") => { |_| NotifyValue::new() } |
             call!(NotifyValue::parse_list))
    }

    fn parse_list(mut input: &[u8]) -> IResult<&[u8], NotifyValue> {
        let mut res = NotifyValue::new();
        let mut first = true;

        loop {
            if !first {
                match chr(input, b',') {
                    Incomplete(n) => { return Incomplete(n) }
                    Error(_) => { return Done(input, res) }
                    Done(rest, _) => { input = rest }
                }
            }
            let step: IResult<&[u8], ()> = alt!(input,
                call!(text, b"SUCCESS") => {
                    |_| { res.success = true; () }
                } |
                call!(text, b"FAILURE") => {
                    |_| { res.failure = true; () }
                } |
                call!(text, b"DELAY") => {
                    |_| { res.delay = true; () }
                }
            );
            match step {
                Incomplete(n) => { return Incomplete(n) }
                Error(_) => {
                    // Allow a trailing comma
                    return Done(input, res)
                }
                Done(rest, _) => { input = rest }
            }
            first = false;
        }
    }
}


/// The Orcpt parameter to the ESMTP RCPT command
///
/// See RFC 3461, section 4.2.
///
#[derive(Debug)]
pub struct OrcptParameter<'a> {
    pub addr_type: DsnAddressType,
    pub addr: Xtext<'a>,
}

impl<'a> OrcptParameter<'a> {
    /// > original-recipient-address = addr-type ";" xtext
    /// > addr-type = atom
    ///
    pub fn parse(input: &'a[u8]) -> IResult<&'a[u8], OrcptParameter<'a>> {
        chain!(input,
               addr_type: call!(DsnAddressType::parse) ~
               call!(chr, b';') ~
               addr: call!(Xtext::parse),
               || OrcptParameter { addr_type: addr_type, addr: addr })
    }
}


/// DSN Address Types
///
/// https://www.iana.org/assignments/dsn-types/dsn-types.xhtml#dsn-types-1
///
#[derive(Debug)]
pub enum DsnAddressType {
    Rfc822,
    X400,
    Utf8
}

impl DsnAddressType {
    pub fn parse(input: &[u8]) -> IResult<&[u8], DsnAddressType> {
        alt!(input,
             call!(text, b"rfc822") => { |_| DsnAddressType::Rfc822 } |
             call!(text, b"x400") => { |_| DsnAddressType::X400 } |
             call!(text, b"utf-8") => { |_| DsnAddressType::Utf8 })
    }
}


//------------ VrfyParameters -----------------------------------------------

#[derive(Debug)]
pub struct VrfyParameters {
    pub smtputf8: Option<()>,
}

impl VrfyParameters {
    pub fn parse(input: &[u8]) -> IResult<&[u8], VrfyParameters> {
        let (output, res) = try_parse!(input,
            opt!(chain!(wsps ~ res: call!(text, b"SMTPUTF8"),
                        || res)));
        Done(output, VrfyParameters { smtputf8: res.map(|_| ()) })
    }
}


//------------ ExpnParameters -----------------------------------------------

#[derive(Debug)]
pub struct ExpnParameters {
    pub smtputf8: Option<()>,
}

impl ExpnParameters {
    pub fn parse(input: &[u8]) -> IResult<&[u8], ExpnParameters> {
        let (output, res) = try_parse!(input,
            opt!(chain!(wsps ~ res: call!(text, b"SMTPUTF8"),
                        || res)));
        Done(output, ExpnParameters { smtputf8: res.map(|_| ()) })
    }
}


//------------ Xtext --------------------------------------------------------

#[derive(Debug)]
pub struct Xtext<'a>(&'a[u8]);

impl<'a> Xtext<'a> {
    /// Parses an xtext.
    ///
    /// > xtext           = *( xchar / hexchar )
    /// > xchar           = %d33-42 / %d44-60 / %d62-126
    /// > hexchar         = "+" 2(%d48-57 / %d65-70)
    ///
    /// Defined in RFC 3461.
    ///
    pub fn parse(input: &[u8]) -> IResult<&[u8], Xtext> {
        let (output, res) = try_parse!(input,
                                       call!(opt_cat_chrs, test_xchar));
        Done(output, Xtext(res))
    }
}

fn test_xchar(chr: u8) -> Result<u8, ErrorKind> {
    if (chr >= 33 && chr <= 60) || (chr >= 62 && chr <= 126) {
        Ok(chr)
    }
    else {
        Err(ErrorKind::Char)
    }
}


//------------ ReversePath --------------------------------------------------

#[derive(Debug)]
pub enum ReversePath<'a> {
    Path(Path<'a>),
    Empty
}

impl<'a> ReversePath<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], ReversePath<'a>> {
        alt!(input,
             tag_bytes!(b"<>") => { |_| ReversePath::Empty } |
             call!(Path::parse) => { |res| ReversePath::Path(res) })
    }
}


//------------ Path ---------------------------------------------------------

#[derive(Debug)]
pub struct Path<'a> (Mailbox<'a>);

impl<'a> Path<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], Path<'a>> {
        delimited!(input,
                   call!(chr, b'<'),
                   chain!(opt!(chain!(a_d_l ~ call!(chr, b':'), || ())) ~
                          mailbox: call!(Mailbox::parse),
                          || Path(mailbox)),
                   call!(chr, b'>'))
    }
}

fn a_d_l(input: &[u8]) -> IResult<&[u8], ()> {
    let (mut output, _) = try_parse!(input, at_domain);
    loop {
        match chr(output, b',') {
            Incomplete(n) => { return Incomplete(n) }
            Error(_) => { return Done(output, ()) }
            Done(rest, _) => { output = rest }
        }
        let (rest, _) = try_parse!(output, at_domain);
        output = rest;
    }
}

fn at_domain(input: &[u8]) -> IResult<&[u8], ()> {
    let (output, _) = try_parse!(input, call!(chr, b'@'));
    let (output, _) = try_parse!(output, call!(Domain::parse));
    Done(output, ())
}


//------------ Domain -------------------------------------------------------

#[derive(Debug)]
pub struct Domain<'a>(&'a[u8]);

impl<'a> Domain<'a> {
    pub fn parse(input: &'a[u8]) -> IResult<&[u8], Domain<'a>> {
        let (mut output, _) = try_parse!(input, sub_domain);
        loop {
            match chr(output, b'.') {
                Incomplete(n) => { return Incomplete(n) }
                Error(_) => { break }
                Done(rest, _) => {
                    output = rest;
                }
            }
            let (rest, _) = try_parse!(output, sub_domain);
            output = rest;
        }
        let (left, right) = input.split_at(input.len() - output.len());
        Done(right, Domain(left))
    }
}

fn sub_domain(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (output, _) = try_parse!(input, alpha_digit);
    let (output, _) = try_parse!(output, ldh_str);
    let (left, right) = input.split_at(input.len() - output.len());
    Done(right, left)
}


//------------ MailboxDomain ------------------------------------------------

#[derive(Debug)]
pub enum MailboxDomain<'a> {
    Domain(Domain<'a>),
    Address(AddressLiteral<'a>),
}

impl<'a> MailboxDomain<'a> {
    pub fn parse(input: &'a[u8]) -> IResult<&[u8], MailboxDomain<'a>> {
        alt!(input,
             call!(Domain::parse) => {
                 |res| MailboxDomain::Domain(res)
             } |
             call!(AddressLiteral::parse) => {
                 |res| MailboxDomain::Address(res)
             })
    }
}


//------------ Mailbox ------------------------------------------------------

#[derive(Debug)]
pub struct Mailbox<'a> {
    local: LocalPart<'a>,
    domain: MailboxDomain<'a>,
}

impl<'a> Mailbox<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], Mailbox<'a>> {
        chain!(input,
               local: call!(LocalPart::parse) ~
               call!(chr, b'@') ~
               domain: call!(MailboxDomain::parse),
               || Mailbox { local: local, domain: domain })
    }
}


//------------ LocalPart ----------------------------------------------------

#[derive(Debug)]
pub enum LocalPart<'a> {
    Dotted(&'a [u8]),
    Quoted(QuotedString<'a>),
}

impl<'a> LocalPart<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], LocalPart<'a>> {
        alt!(input, call!(LocalPart::parse_dot_string) |
                    map!(QuotedString::parse, |res| LocalPart::Quoted(res)))
    }

    pub fn parse_dot_string(input: &'a [u8]) -> IResult<&[u8], LocalPart<'a>> {
        let (mut output, _) = try_parse!(input, atom);
        loop {
            match chr(output, b'.') {
                Incomplete(n) => { return Incomplete(n) }
                Error(_) => { break }
                Done(rest, _) => {
                    output = rest;
                }
            }
            let (rest, _) = try_parse!(output, atom);
            output = rest;
        }
        let (left, right) = input.split_at(input.len() - output.len());
        Done(right, LocalPart::Dotted(left))
    }
}


pub fn test_atext(chr: u8) -> Result<u8, ErrorKind> {
    if (chr >= 0x21 && chr <= 0x27) || chr == 0x2A || chr == 0x2B ||
       chr == 0x2D || (chr >= 0x2F && chr <= 0x39) || chr == 0x3D ||
       chr == 0x3F || (chr >= 0x41 && chr <= 0x5A) ||
       (chr >= 0x5E && chr <= 0x7E) || chr >= 0x80
    {
        Ok(chr)
    }
    else {
        Err(ErrorKind::Char)
    }
}

pub fn atom(input: &[u8]) -> IResult<&[u8], &[u8]> {
    cat_chrs(input, test_atext)
}


//------------ QuotedString -------------------------------------------------

#[derive(Debug)]
pub struct QuotedString<'a> (&'a [u8]);

impl<'a> QuotedString<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], QuotedString<'a>> {
        let (output, res) = try_parse!(input, 
            delimited!(call!(chr, b'"'),
                       escaped!(call!(cat_chr, qtext), b'\\',
                                call!(cat_chr, quoted_char)),
                       call!(chr, b'"')));
            Done(output, QuotedString(res))
    }
}

fn qtext(chr: u8) -> Result<u8, ErrorKind> {
    if chr == 32 || chr == 33 || (chr >= 35 && chr <= 91) ||
            (chr >= 93 && chr <= 126) || chr >= 0x80 {
        Ok(chr)
    }
    else {
        Err(ErrorKind::Char)
    }
}

fn quoted_char(chr: u8) -> Result<u8, ErrorKind> {
    if chr >= 32 && chr <= 126 { Ok(chr) }
    else { Err(ErrorKind::Char) }
}


//------------ Word ---------------------------------------------------------

/// A word. RFC 5321 calls it a ‘String.’
///
/// > String         = Atom / Quoted-string
///
#[derive(Debug)]
pub enum Word<'a> {
    Atom(&'a[u8]),
    Quoted(QuotedString<'a>)
}

impl<'a> Word<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], Word<'a>> {
        alt!(input,
             map!(atom, |res| Word::Atom(res)) |
             map!(QuotedString::parse, |res| Word::Quoted(res)))
    }
}


//------------ AdressLiteral ------------------------------------------------

#[derive(Debug)]
pub enum AddressLiteral<'a> {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    General { tag: &'a [u8], content: &'a [u8] },
}

impl<'a> AddressLiteral<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&[u8], AddressLiteral<'a>> {
        use util::abnf::ipaddr::{ipv4_addr, ipv6_addr};

        delimited!(input,
            call!(chr, b'['),
            alt!(map!(ipv4_addr, |addr| AddressLiteral::Ipv4(addr)) |
                 chain!(call!(text, b"IPv6:") ~ addr: ipv6_addr,
                        || AddressLiteral::Ipv6(addr)) |
                 chain!(tag: ldh_str ~ call!(chr, b':') ~ content: dcontents,
                        || AddressLiteral::General { tag: tag,
                                                     content: content })),
            call!(chr, b']'))
    }
}

fn test_dcontent(chr: u8) -> Result<u8, ErrorKind> {
    if (chr >= 33 && chr <= 90) || (chr >= 94 && chr <= 126) {
        Ok(chr)
    }
    else {
        Err(ErrorKind::Char)
    }
}

fn dcontents(input: &[u8]) -> IResult<&[u8], &[u8]> {
    cat_chrs(input, test_dcontent)
}


fn test_ldh_str(chr: u8) -> Result<u8, ErrorKind> {
    if is_alphanumeric(chr) || chr == b'-' { Ok(chr) }
    else { Err(ErrorKind::Char) }
}

fn ldh_str(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (output, _) = try_parse!(input, call!(opt_cat_chrs, test_ldh_str));
    let (output, _) = try_parse!(output, alpha_digit);
    let (left, right) = input.split_at(input.len() - output.len());
    Done(right, left)
}

