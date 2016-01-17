//! Parsers for IPv4 and IPv6 addresses in their usual notation.

use std::net::{Ipv4Addr, Ipv6Addr};
use nom::{IResult, Needed};
use super::core::{chr, u8_digits, u16_hexdigs};

/// Parses an IPv4 address
///
named!(pub ipv4_addr<Ipv4Addr>,
       chain!(a: u8_digits ~ call!(chr, b'.') ~
              b: u8_digits ~ call!(chr, b'.') ~
              c: u8_digits ~ call!(chr, b'.') ~
              d: u8_digits,
              || Ipv4Addr::new(a, b, c, d)));

/// Parses an IPv6 address
///
/// > IPv6-addr      = IPv6-full / IPv6-comp / IPv6v4-full / IPv6v4-comp
///
named!(pub ipv6_addr<Ipv6Addr>,
       alt!(ipv6_full | ipv6_comp | ipv6v4_full | ipv6v4_comp));

/// > IPv6-full      = IPv6-hex 7(":" IPv6-hex)
named!(ipv6_full<Ipv6Addr>,
       chain!(a: u16_hexdigs ~ call!(chr, b':') ~
              b: u16_hexdigs ~ call!(chr, b':') ~
              c: u16_hexdigs ~ call!(chr, b':') ~
              d: u16_hexdigs ~ call!(chr, b':') ~
              e: u16_hexdigs ~ call!(chr, b':') ~
              f: u16_hexdigs ~ call!(chr, b':') ~
              g: u16_hexdigs ~ call!(chr, b':') ~
              h: u16_hexdigs,
              || Ipv6Addr::new(a, b, c, d, e, f, g, h)));


/// > IPv6-comp      = [IPv6-hex *5(":" IPv6-hex)] "::"
/// >                  [IPv6-hex *5(":" IPv6-hex)]
///
fn ipv6_comp(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (input, (mut left, left_count)) =
                                  try_parse!(input, call!(ipv6_comp_left, 6));
    let (input, (right, right_count)) =
                    try_parse!(input, call!(ipv6_comp_right, 6 - left_count));
    for i in 0..right_count {
        left[8 - right_count + i] = right[i]
    }
    IResult::Done(input, Ipv6Addr::new(left[0], left[1], left[2], left[3],
                                       left[4], left[5], left[6], left[7]))
}



/// > IPv6v4-full    = IPv6-hex 5(":" IPv6-hex) ":" IPv4-address-literal
named!(pub ipv6v4_full<Ipv6Addr>,
       chain!(a: u16_hexdigs ~ call!(chr, b':') ~
              b: u16_hexdigs ~ call!(chr, b':') ~
              c: u16_hexdigs ~ call!(chr, b':') ~
              d: u16_hexdigs ~ call!(chr, b':') ~
              e: u16_hexdigs ~ call!(chr, b':') ~
              f: u16_hexdigs ~ call!(chr, b':') ~
              g1: u8_digits ~ call!(chr, b'.') ~
              g2: u8_digits ~ call!(chr, b'.') ~
              h1: u8_digits ~ call!(chr, b'.') ~
              h2: u8_digits,
              || Ipv6Addr::new(a, b, c, d, e, f,
                               (g1 as u16) << 8 | (g2 as u16),
                               (h1 as u16) << 8 | (h2 as u16))));


/// > IPv6v4-comp    = [IPv6-hex *3(":" IPv6-hex)] "::"
/// >                  [IPv6-hex *3(":" IPv6-hex) ":"]
/// >                  IPv4-address-literal
fn ipv6v4_comp(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (input, (mut left, left_count)) =
                                  try_parse!(input, call!(ipv6_comp_left, 4));
    let (input, (right, right_count)) =
                    try_parse!(input, call!(ipv6_comp_right, 4 - left_count));
    let (input, v4) = try_parse!(input, ipv4_addr);
    let v4 = v4.octets();
    for i in 0..right_count {
        left[6 - right_count + i] = right[i];
    }
    left[6] = (v4[0] as u16) << 8 | (v4[1] as u16);
    left[7] = (v4[2] as u16) << 8 | (v4[3] as u16);
    IResult::Done(input, Ipv6Addr::new(left[0], left[1], left[2], left[3],
                                       left[4], left[5], left[6], left[7]))
}


/// Parses the left hand side of a compressed IPv6 address.
///
/// Returns the parsed components and the number of them.
///
fn ipv6_comp_left(mut input: &[u8], max: usize)
                  -> IResult<&[u8], ([u16; 8], usize)> {
    let mut res = [0u16, 0, 0, 0, 0, 0, 0, 0];

    // Minimum size is two: b"::" or b"0:"
    if input.len() < 3 { return IResult::Incomplete(Needed::Size(2)) }

    // We may start with two colons, in which case there is no left hand
    // side.
    if input[0] == b':' && input[1] == b':' {
        return IResult::Done(&input[2..], (res, 0));
    }

    // Up to six components that end in a colon and may end in a
    // double colon
    for i in 0..max {
        let (rest, v) = try_parse!(input, u16_hexdigs);
        let (rest, _) = try_parse!(rest, call!(chr, b':'));
        input = rest;
        res[i] = v;

        if input.first() == Some(&b':') {
            return IResult::Done(&input[1..], (res, i + 1));
        }
    }

    IResult::Done(input, (res, max))
}


/// Parses the right hand side of a compressed IPv6 address.
///
/// Returns the parsed components and the number of them.
///
fn ipv6_comp_right(mut input: &[u8], max: usize)
                   -> IResult<&[u8], ([u16; 8], usize)> {
    let mut res = [0u16, 0, 0, 0, 0, 0, 0, 0];

    for i in 0..max {
        match u16_hexdigs(input) {
            IResult::Incomplete(n) => { return IResult::Incomplete(n) }
            IResult::Error(e) => {
                if i == 0 {
                    return IResult::Done(input, (res, 0))
                }
                else {
                    return IResult::Error(e)
                }
            }
            IResult::Done(rest, v) => {
                input = rest;
                res[i] = v;
            }
        }
        match chr(input, b':') {
            IResult::Done(rest, _) => {
                if i == max - 1 { break; }
                else { input = rest; }
            }
            _ => { return IResult::Done(input, (res, i + 1)); }
        }
    }
    return IResult::Done(input, (res, max))
}


//============ Test =========================================================

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use nom::IResult;
    use super::*;

    #[test]
    pub fn ipv4_good() {
        assert_eq!(ipv4_addr(b"127.0.0.1 "),
                   IResult::Done(&b" "[..],
                                 Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    pub fn ipv6_good() {
        assert_eq!(ipv6_addr(b"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210 "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0xFEDC, 0xBA98, 0x7654,
                                               0x3210, 0xFEDC, 0xBA98,
                                               0x7654, 0x3210)));
        assert_eq!(ipv6_addr(b"1080:0:0:0:8:800:200C:417A "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0x1080, 0, 0, 0,
                                               8, 0x800, 0x200C, 0x417A)));
        assert_eq!(ipv6_addr(b"1080::8:800:200C:417A "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0x1080, 0, 0, 0,
                                               8, 0x800, 0x200C, 0x417A)));
        assert_eq!(ipv6_addr(b"FF01::43 "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0xFF01, 0, 0, 0,
                                               0, 0, 0, 0x43)));
        assert_eq!(ipv6_addr(b"::1 "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert_eq!(ipv6_addr(b":: "),
                   IResult::Done(&b" "[..],
                                 Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
    }
}
