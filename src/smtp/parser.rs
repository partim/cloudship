use nom::{self, crlf, space, IResult};
use super::protocol::Command;


//------------ Macros -------------------------------------------------------

/// `text!(&[T]: nom::AsBytes) => &[T] -> IResult<&[T], &[T]>`
/// declares a byte array as a suite to recognize ignoring case for ASCII
/// characters
///
/// consumes the recognized characters
///
macro_rules! text (
    ($i:expr, $inp: expr) => (
        {
            #[inline(always)]
            fn as_bytes<T: nom::AsBytes>(b: &T) -> &[u8] {
                b.as_bytes()
            }

            let expected = $inp;
            let bytes = as_bytes(&expected);

            text_bytes!($i, bytes)
        }
    );
);

macro_rules! text_bytes (
    ($i:expr, $bytes: expr) => (
        {
            use std::cmp::min;
            use std::ascii::AsciiExt;
            let len = $i.len();
            let blen = $bytes.len();
            let m = min(len, blen);
            let reduced = &$i[..m];
            let b = &$bytes[..m];

            let res : nom::IResult<&[u8],&[u8]> =
                if !reduced.eq_ignore_ascii_case(b) {
                    nom::IResult::Error(
                        nom::Err::Position(
                            nom::ErrorKind::Tag, $i))
                } else if m < blen {
                    nom::IResult::Incomplete(nom::Needed::Size(blen))
                } else {
                    nom::IResult::Done(&$i[blen..], reduced)
                };
            res
        }
    );
);

/// `empty_command!(&[T]: nom::AsBytes) =>
///                                 &[T] -> IResult<&[T], ::CommandResult>
///
/// The command $verb without parameters resulting in $result
///
macro_rules! empty_command (
    ($i:expr, $verb: expr, $result: expr) => (
        alt!($i,
            chain!(text!($verb) ~ wscrlf, || Ok($result)) |
            chain!(text!($verb) ~ take_until_and_consume!(b"\r\n"),
                   || Err(CommandError::Parameters))
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
            chain!(text!($verb) ~ res: $($rest)*, || res) |
            chain!(text!($verb) ~ take_until_and_consume!(b"\r\n"),
                   || Err(CommandError::Parameters))
        )
    );
);

//------------ Parser Functions ---------------------------------------------

#[derive(Debug)]
pub enum CommandError {
    /// "Syntax error, command unrecognized" (500)
    Syntax,

    /// "Syntax error in parameters or arguments" (501)
    Parameters,
}

pub type CommandResult<'a> = Result<Command<'a>, CommandError>;

pub fn parse_command<'a>(i: &'a [u8]) -> IResult<&'a [u8], CommandResult<'a>> {
    alt!(i, 
        command!("EHLO",
            map!(take_until_and_consume!(b"\r\n"), 
                   |res| Ok(Command::Ehlo { domain: res }))
        ) |
        empty_command!("QUIT", Command::Quit) |
        map!(take_until_and_consume!(b"\r\n"), |_| Err(CommandError::Syntax))
    )
}


/// Parses a sequence of optional white-space followed by CRLF.
///
named!(pub wscrlf<()>, chain!(opt!(space) ~ crlf, || ()));


//------------ Test ---------------------------------------------------------


