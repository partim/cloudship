//! Traits to construct text-based messages

//------------ Scribe -------------------------------------------------------

/// A trait for something into which text-messages can be assembled.
///
/// A type implementing this trait serves as a buffer to assemble the message
/// before sending. Putting the message together shall be called "scribbling"
/// and types that can turn themselves into parts of such a text messages are
/// `Scribble`s. 
///
/// Note that this here isn’t serialization (which is why different terms
/// have been chosen) since there is no generic way to express any Rust type.
/// Only specific types can be scribbled.
///
/// The trait provides implementations for a few builtin primitive types in
/// a way typical for Internet messages. You can overide these of necessary
/// for your specific format.
///
pub trait Scribe {

    //--- Required Methods

    /// Attach a `u8` slice to the end of the message.
    fn scribble_bytes(&mut self, buf: &[u8]);

    /// Attach a single byts as is to the end of the message.
    ///
    /// Note that this differs from `scribble_u8()` which attaches the
    /// decimal representation of the value.
    ///
    fn scribble_octet(&mut self, v: u8);


    //--- Provided Methods

    /// Scribble a bool.
    ///
    /// This implementation uses `0` for `false` and `1` for `true`.
    ///
    fn scribble_bool(&mut self, v: bool) {
        match v {
            true => self.scribble_octet(b'1'),
            false => self.scribble_octet(b'0'),
        }
    }

    // Unsigned integers.
    // 
    // These implementations use the decimal form of the number.
    //
    // All smaller types are implemented by casting to `u64`.
    //
    fn scribble_u64(&mut self, v: u64) {
        let u = v / 10;
        if u > 0 {
            self.scribble_u64(u);
        }
        self.scribble_octet((v % 10) as u8 + b'0')
    }
    fn scribble_u32(&mut self, v: u32) { self.scribble_u64(v as u64) }
    fn scribble_u16(&mut self, v: u16) { self.scribble_u64(v as u64) }
    fn scribble_u8(&mut self, v: u8) { self.scribble_u64(v as u64) }
    fn scribble_usize(&mut self, v: usize) { self.scribble_u64(v as u64) }

    // Signed integers.
    //
    // These implementations use the decimal form of the number prefixed
    // by `-` if the number is negative.
    //
    // All smaller types are implemented by casing to `i64`
    //
    fn scribble_i64(&mut self, mut v: i64) {
        if v < 0 {
            self.scribble_octet(b'-');
            v = -v;
        }
        self.scribble_u64(v as u64);
    }
    fn scribble_i32(&mut self, v: i32) { self.scribble_i64(v as i64) }
    fn scribble_i16(&mut self, v: i16) { self.scribble_i64(v as i64) }
    fn scribble_i8(&mut self, v: i8) { self.scribble_i64(v as i64) }
    fn scribble_isize(&mut self, v: isize) { self.scribble_i64(v as i64) }

    /// Scribble a string.
    ///
    /// This implementation simply uses the UTF-8 encoding of the string.
    ///
    fn scribble_str(&mut self, v: &str) {
        self.scribble_bytes(v.as_bytes())
    }
}


//------------ Scribble -----------------------------------------------------

/// A trait for a type that can be scribbled.
///
pub trait Scribble {
    fn scribble<S: Scribe>(&self, scribe: &mut S);
}

//--- Scribble implementations for primitive types
//
// There is no implementatin for u8 since these can be ambiguous.
//

macro_rules! impl_scribble {
    ($ty:ty, $method:ident) => {
        impl Scribble for $ty {
            #[inline]
            fn scribble<S: Scribe>(&self, scribe: &mut S) {
                scribe.$method(*self);
            }
        }
    }
}

impl_scribble!(bool, scribble_bool);
impl_scribble!(u64, scribble_u64);
impl_scribble!(u32, scribble_u32);
impl_scribble!(u16, scribble_u16);
impl_scribble!(usize, scribble_usize);
impl_scribble!(i64, scribble_i64);
impl_scribble!(i32, scribble_i32);
impl_scribble!(i16, scribble_i16);
impl_scribble!(i8, scribble_i8);
impl_scribble!(isize, scribble_isize);


//--- Scribble implementations for comples types

impl Scribble for [u8] {
    fn scribble<S: Scribe>(&self, scribe: &mut S) {
        scribe.scribble_bytes(self);
    }
}

impl Scribble for str {
    fn scribble<S: Scribe>(&self, scribe: &mut S) {
        scribe.scribble_str(self);
    }
}

