/// Tools for working with our script syntax.
///
/// The script syntax we use provides the ability to run multiple commands in a scripting format
/// and get the results in a machine-parseable way.
///
/// All fields in this format are space-separated, and each command or response is a single line
/// (terminated with LF).  Multiple responses are permissible if the data is best spread over
/// multiple lines.
///
/// Encoding of integers may be done as decimals (no prefix), hex (with `0x`), or octal (with
/// `0o`).  Encoding of text strings and byte strings uses percent-encoding with lowercase text for
/// all control characters, percent and space.  Optional values are encoded as `nil` for `None` and
/// with the value preceded by `@` for `Some`.
///
/// A request contains a string tag, a string command, and any number of arguments specific to the
/// command.  A successful response to a request repeats the tag, includes the string `ok`, and
/// then provides any relevant arguments.  An unsuccessful response to a request repeats the tag,
/// includes the string `err`, includes a colon-separated set of error types (classes of error, if
/// you will), a string error tag (representing the specific error), and a string error message.
use bytes::Bytes;
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid integer in field {0}")]
    InvalidInteger(usize),
    #[error("invalid boolean in field {0}")]
    InvalidBoolean(usize),
    #[error("invalid UTF-8 in field {0}")]
    InvalidUTF8(usize),
    #[error("invalid option in field {0}")]
    InvalidOption(usize),
    #[error("unexpected end of stream")]
    UnexpectedEndOfStream,
    #[error("unexpected value at offset {0}")]
    UnexpectedValue(usize),
    #[error("missing newline")]
    MissingNewline,
    #[error("unsupported type")]
    UnsupportedType(Cow<'static, str>),
    #[error("invalid escaped string")]
    InvalidEscapedString(usize),
}

pub trait Encodable {
    fn encode(&self) -> Cow<'_, [u8]>;
    fn encode_to_bytes(&self) -> Bytes {
        self.encode().into_owned().into()
    }
}

#[derive(Default)]
pub struct ScriptEncoder {}

impl ScriptEncoder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn encode<'a, T: Encodable>(&self, val: &'a T) -> Cow<'a, [u8]>
    where
        T: ?Sized,
    {
        val.encode()
    }

    pub fn encode_to_bytes<T: Encodable>(&self, val: &T) -> Bytes
    where
        T: ?Sized,
    {
        val.encode_to_bytes()
    }

    fn encode_bytes(bs: &[u8]) -> Vec<u8> {
        const OFFSET: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 3];
        let mut v = Vec::with_capacity(bs.len() + 10);
        for b in bs {
            let encoded: &[u8] = match b {
                b if b.is_ascii_control() => {
                    buf = [b'%', OFFSET[(b >> 4) as usize], OFFSET[(b & 0xf) as usize]];
                    &buf
                }
                b'%' | b' ' => {
                    buf = [b'%', OFFSET[(b >> 4) as usize], OFFSET[(b & 0xf) as usize]];
                    &buf
                }
                b => {
                    buf[0] = *b;
                    &buf[0..1]
                }
            };
            v.extend(encoded);
        }
        v
    }
}

macro_rules! encode_int {
    ($a:ty) => {
        impl Encodable for $a {
            fn encode(&self) -> Cow<'_, [u8]> {
                Cow::Owned(format!("{}", self).into_bytes())
            }
        }
    };
}

encode_int!(u8);
encode_int!(u16);
encode_int!(u32);
encode_int!(u64);
encode_int!(u128);
encode_int!(i8);
encode_int!(i16);
encode_int!(i32);
encode_int!(i64);
encode_int!(i128);

impl Encodable for str {
    fn encode(&self) -> Cow<'_, [u8]> {
        Cow::Owned(ScriptEncoder::encode_bytes(self.as_bytes()))
    }
}

impl Encodable for String {
    fn encode(&self) -> Cow<'_, [u8]> {
        Cow::Owned(ScriptEncoder::encode_bytes(self.as_bytes()))
    }
}

impl Encodable for [u8] {
    fn encode(&self) -> Cow<'_, [u8]> {
        Cow::Owned(ScriptEncoder::encode_bytes(self))
    }
}

impl Encodable for Vec<u8> {
    fn encode(&self) -> Cow<'_, [u8]> {
        Cow::Owned(ScriptEncoder::encode_bytes(self.as_slice()))
    }
}

impl Encodable for Bytes {
    // TODO: encode properly.
    fn encode(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_ref())
    }
}

pub struct ScriptDeserializer<'de> {
    line: &'de [u8],
    offset: AtomicUsize,
    field_offset: AtomicUsize,
}

impl<'de> ScriptDeserializer<'de> {
    pub fn new(line: &'de [u8]) -> Self {
        Self {
            line,
            offset: AtomicUsize::new(0),
            field_offset: AtomicUsize::new(0),
        }
    }

    pub fn parse<'a: 'de, T: Parseable<'a, 'de>>(&'a self) -> Result<T, Error> {
        T::from_deserializer(self)
    }

    pub fn parse_owned<T: ParseableOwned>(&self) -> Result<T, Error> {
        T::from_deserializer(self)
    }

    fn next_err(&self) -> Result<(&[u8], usize), Error> {
        self.next().ok_or(Error::UnexpectedEndOfStream)
    }

    fn next(&self) -> Option<(&[u8], usize)> {
        // The updating of offset here is not thread-safe, but we know this will never be used from
        // multiple threads at a time.
        let offset = self.offset.load(Ordering::Acquire);
        if offset == self.line.len() {
            return None;
        }
        match self.line[offset..].split(|b| *b == b' ').next() {
            Some(item) => {
                let field_offset = self.field_offset.fetch_add(1, Ordering::AcqRel);
                if offset + item.len() >= self.line.len() {
                    self.offset.store(self.line.len(), Ordering::Release);
                } else {
                    self.offset.fetch_add(item.len() + 1, Ordering::AcqRel);
                }
                Some((item, field_offset))
            }
            None => None,
        }
    }

    // Using the same function is nicer than mixing and matching.
    #[allow(clippy::from_str_radix_10)]
    fn parse_signed<T: TryFrom<i128>>(&self, src: &[u8], offset: usize) -> Result<T, Error> {
        let data = std::str::from_utf8(src).map_err(|_| Error::InvalidInteger(offset))?;
        let value = if data.starts_with("0x") {
            i128::from_str_radix(&data[2..], 16)
        } else if data.starts_with("0o") {
            i128::from_str_radix(&data[2..], 8)
        } else {
            i128::from_str_radix(&data, 10)
        };
        value
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::InvalidInteger(offset))
    }

    // Using the same function is nicer than mixing and matching.
    #[allow(clippy::from_str_radix_10)]
    fn parse_unsigned<T: TryFrom<u128>>(&self, src: &[u8], offset: usize) -> Result<T, Error> {
        let data = std::str::from_utf8(src).map_err(|_| Error::InvalidInteger(offset))?;
        let value = if data.starts_with("0x") {
            u128::from_str_radix(&data[2..], 16)
        } else if data.starts_with("0o") {
            u128::from_str_radix(&data[2..], 8)
        } else {
            u128::from_str_radix(&data, 10)
        };
        value
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(Error::InvalidInteger(offset))
    }

    fn parse_bytes<'a>(&self, src: &'a [u8], offset: usize) -> Result<Cow<'a, [u8]>, Error> {
        if src.iter().any(|b| *b == b'%') {
            fn parse_hex(a: u8, b: u8, offset: usize) -> Result<u8, Error> {
                if (a.is_ascii_digit() || (b'a'..=b'f').contains(&a))
                    && (b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    let seq: &[u8] = &[a, b];
                    let s = unsafe { std::str::from_utf8_unchecked(seq) };
                    u8::from_str_radix(s, 16).map_err(|_| Error::InvalidEscapedString(offset))
                } else {
                    Err(Error::InvalidEscapedString(offset))
                }
            }

            let mut v = Vec::with_capacity(src.len() + 10);
            let mut bs = src.iter();
            loop {
                let b = bs.next();
                match b {
                    Some(b'%') => match (bs.by_ref().next(), bs.by_ref().next()) {
                        (Some(a), Some(b)) => v.push(parse_hex(*a, *b, offset)?),
                        _ => return Err(Error::InvalidEscapedString(offset)),
                    },
                    Some(b) => v.push(*b),
                    None => break,
                }
            }
            Ok(Cow::Owned(v))
        } else {
            Ok(Cow::Borrowed(src))
        }
    }

    fn parse_str<'a>(&self, src: &'a [u8], offset: usize) -> Result<Cow<'a, str>, Error> {
        match self.parse_bytes(src, offset)? {
            Cow::Borrowed(b) => Ok(Cow::Borrowed(
                std::str::from_utf8(b).map_err(|_| Error::InvalidUTF8(offset))?,
            )),
            Cow::Owned(b) => Ok(Cow::Owned(
                String::from_utf8(b).map_err(|_| Error::InvalidUTF8(offset))?,
            )),
        }
    }
}

pub trait Parseable<'a: 'de, 'de> {
    fn from_sequence(
        de: &'a ScriptDeserializer<'de>,
        src: &'de [u8],
        offset: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_deserializer(de: &'a ScriptDeserializer<'de>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (val, off) = de.next_err()?;
        Self::from_sequence(de, val, off)
    }
}

pub trait ParseableOwned {
    fn from_sequence<'de>(
        de: &ScriptDeserializer<'de>,
        src: &'de [u8],
        offset: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized;
    fn from_deserializer(de: &ScriptDeserializer<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let (val, off) = de.next_err()?;
        Self::from_sequence(de, val, off)
    }
}

impl<'a: 'de, 'de> Parseable<'a, 'de> for Cow<'de, str> {
    fn from_sequence(
        de: &'a ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        de.parse_str(val, off)
    }
}

impl ParseableOwned for String {
    fn from_sequence<'de>(
        de: &ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(de.parse_str(val, off)?.into_owned())
    }
}

impl<'a: 'de, 'de> Parseable<'a, 'de> for Cow<'de, [u8]> {
    fn from_sequence(
        de: &'a ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        de.parse_bytes(val, off)
    }
}

impl ParseableOwned for Vec<u8> {
    fn from_sequence<'de>(
        de: &ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(de.parse_bytes(val, off)?.into_owned())
    }
}

impl ParseableOwned for Bytes {
    fn from_sequence<'de>(
        de: &ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(Bytes::from(de.parse_bytes(val, off)?.into_owned()))
    }
}

impl ParseableOwned for bool {
    fn from_sequence<'de>(
        _de: &ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match val {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => Err(Error::InvalidBoolean(off)),
        }
    }
}

macro_rules! parse_signed {
    ($a:ty) => {
        impl ParseableOwned for $a {
            fn from_sequence<'de>(
                de: &ScriptDeserializer<'de>,
                val: &'de [u8],
                off: usize,
            ) -> Result<Self, Error>
            where
                Self: Sized,
            {
                de.parse_signed(val, off)
            }
        }
    };
}

macro_rules! parse_unsigned {
    ($a:ty) => {
        impl ParseableOwned for $a {
            fn from_sequence<'de>(
                de: &ScriptDeserializer<'de>,
                val: &'de [u8],
                off: usize,
            ) -> Result<Self, Error>
            where
                Self: Sized,
            {
                de.parse_unsigned(val, off)
            }
        }
    };
}

parse_signed!(i8);
parse_signed!(i16);
parse_signed!(i32);
parse_signed!(i64);
parse_signed!(i128);

parse_unsigned!(u8);
parse_unsigned!(u16);
parse_unsigned!(u32);
parse_unsigned!(u64);
parse_unsigned!(u128);

impl<T> ParseableOwned for Option<T>
where
    T: ParseableOwned,
{
    fn from_sequence<'de>(
        de: &ScriptDeserializer<'de>,
        val: &'de [u8],
        off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        if val == b"nil" {
            Ok(None)
        } else if val.starts_with(b"@") && val.len() > 1 {
            Ok(Some(T::from_sequence(de, &val[1..], off)?))
        } else {
            Err(Error::InvalidOption(off))
        }
    }
    fn from_deserializer(de: &ScriptDeserializer<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match de.next() {
            Some((val, off)) => Self::from_sequence(de, val, off),
            None => Ok(None),
        }
    }
}

impl ParseableOwned for () {
    fn from_sequence<'de>(
        _de: &ScriptDeserializer<'de>,
        _val: &'de [u8],
        _off: usize,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Err(Error::UnsupportedType(Cow::Borrowed("tuple")))
    }
    fn from_deserializer(de: &ScriptDeserializer<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match de.next() {
            Some((_, off)) => Err(Error::UnexpectedValue(off)),
            None => Ok(()),
        }
    }
}

macro_rules! as_next {
    ($de:ident, $t:ty) => {{
        let v = $de.next_err()?;
        <$t>::from_sequence($de, v.0, v.1)?
    }};
}

// Based on Rust's src/core/tuple.rs.
macro_rules! tuple_impls {
    ($T:ident) => {
        tuple_impls!(@impl $T);
    };
    // Running criteria (n-ary tuple, with n >= 2)
    ($T:ident $( $U:ident )+) => {
        tuple_impls!($( $U )+);
        tuple_impls!(@impl $T $( $U )+);
    };
    (@impl $( $T:ident )+) => {
        //$($T)+ @
        impl<$($T: ParseableOwned),+> ParseableOwned for ($($T,)+)
        where
            last_type!($($T,)+): ParseableOwned
        {
            fn from_sequence<'de>(
                _de: &ScriptDeserializer<'de>,
                _val: &'de [u8],
                _off: usize,
            ) -> Result<Self, Error>
            where
                Self: Sized,
            {
                Err(Error::UnsupportedType(Cow::Borrowed("tuple")))
            }
            fn from_deserializer(de: &ScriptDeserializer<'_>) -> Result<Self, Error>
            where
                Self: Sized,
            {
                let val = ($(as_next!(de, $T),)+);
                Ok(val)
            }
        }

        impl<'a: 'de, 'de, $($T: Parseable<'a, 'de>),+> Parseable<'a, 'de> for ($($T,)+)
        where
            last_type!($($T,)+): Parseable<'a, 'de>
        {
            fn from_sequence(
                _de: &'a ScriptDeserializer<'de>,
                _val: &'de [u8],
                _off: usize,
            ) -> Result<Self, Error>
            where
                Self: Sized,
            {
                Err(Error::UnsupportedType(Cow::Borrowed("tuple")))
            }
            fn from_deserializer(de: &'a ScriptDeserializer<'de>) -> Result<Self, Error>
            where
                Self: Sized,
            {
                let val = ($(as_next!(de, $T),)+);
                match de.next() {
                    Some((_, off)) => Err(Error::UnexpectedValue(off)),
                    None => Ok(val),
                }
            }
        }
    }
}

macro_rules! last_type {
    ($a:ident,) => { $a };
    ($a:ident, $($rest_a:ident,)+) => { last_type!($($rest_a,)+) };
}

tuple_impls!(T U V W X Y Z A B C D E F G);

#[cfg(test)]
mod tests {
    use super::{ScriptDeserializer, ScriptEncoder};
    use bytes::Bytes;
    use std::borrow::Cow;

    fn parser<'de>(line: &'de [u8]) -> ScriptDeserializer<'de> {
        ScriptDeserializer::new(line)
    }

    #[test]
    fn deserializes_correctly() {
        let p = parser(b"hello world");
        assert_eq!(
            p.parse::<(Cow<'_, str>, Cow<'_, str>)>().unwrap(),
            (Cow::Borrowed("hello"), Cow::Borrowed("world")),
            "hello world tuple"
        );

        let p = parser(b"hello world");
        assert_eq!(
            p.parse_owned::<(String, String)>().unwrap(),
            ("hello".into(), "world".into()),
            "hello world string tuple"
        );

        let p = parser(b"hello%20world");
        assert_eq!(
            p.parse_owned::<String>().unwrap(),
            String::from("hello world"),
            "hello world string"
        );

        let p = parser(b"hello%20world hello%20New%20Jersey");
        assert_eq!(
            p.parse_owned::<(Bytes, Bytes)>().unwrap(),
            (Bytes::from("hello world"), Bytes::from("hello New Jersey")),
            "hello world bytes"
        );

        let p = parser(b"true false 255 0xff00 0o777");
        assert_eq!(
            p.parse_owned::<(bool, bool, u8, u16, i32)>().unwrap(),
            (true, false, 255, 0xff00, 0o777),
            "mixed bools and integers"
        );

        let p = parser(b"nil @bob @0xffff");
        assert_eq!(
            p.parse_owned::<(Option<u8>, Option<String>, Option<u16>)>()
                .unwrap(),
            (None, Some("bob".into()), Some(65535)),
            "options"
        );

        let p = parser(b"true false 255 0xff00 0o777");
        assert_eq!(
            p.parse_owned::<(bool, bool)>().unwrap(),
            (true, false),
            "mixed bools and integers, step 1"
        );
        assert_eq!(
            p.parse_owned::<(u8, u16, i32)>().unwrap(),
            (255, 0xff00, 0o777),
            "mixed bools and integers, step 2"
        );
    }

    #[test]
    fn serializes_correctly() {
        let se = ScriptEncoder::new();
        assert_eq!(se.encode("hello").as_ref(), b"hello", "hello string");
        assert_eq!(
            se.encode(b"hello" as &[u8]).as_ref(),
            b"hello",
            "hello bytes"
        );
        assert_eq!(
            se.encode(b"hello world\n!" as &[u8]).as_ref(),
            b"hello%20world%0a!",
            "hello bytes"
        );
        assert_eq!(se.encode(&0xff).as_ref(), b"255", "integer");
    }
}
