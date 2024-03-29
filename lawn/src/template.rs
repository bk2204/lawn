use crate::encoding::escape;
use bytes::Bytes;
use lawn_constants::error::ExtendedError;
use lawn_protocol::protocol;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

pub struct Template {
    text: Bytes,
    needs_expansion: bool,
}

#[derive(Clone, Copy)]
enum ParsingState {
    Normal,
    Percent,
    OpenParen,
    Inside,
    CloseParen,
}

#[derive(Clone, Debug)]
pub enum Error {
    InvalidCharacter(usize),
    InvalidRadixCharacter,
    UnknownPattern(Bytes),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(off) => {
                write!(f, "invalid character in template at byte {}", off)
            }
            Self::InvalidRadixCharacter => {
                write!(f, "invalid byte when parsing radix")
            }
            Self::UnknownPattern(pattern) => write!(f, "unknown pattern '{}'", escape(pattern)),
        }
    }
}

impl std::error::Error for Error {}

impl ExtendedError for Error {
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("template")])
    }

    fn error_tag(&self) -> Cow<'static, str> {
        match self {
            Self::InvalidCharacter(..) => Cow::Borrowed("invalid-character"),
            Self::InvalidRadixCharacter => Cow::Borrowed("invalid-radix-character"),
            Self::UnknownPattern(..) => Cow::Borrowed("unknown-pattern"),
        }
    }
}

impl Template {
    pub fn new(s: &[u8]) -> Template {
        let expansion = s.iter().any(|&c| c == b'%');
        Template {
            text: s.to_vec().into(),
            needs_expansion: expansion,
        }
    }

    pub fn expand(&self, context: &TemplateContext) -> Result<Bytes, Error> {
        if !self.needs_expansion {
            return Ok(self.text.clone());
        }
        let mut s: Vec<u8> = Vec::with_capacity(self.text.len() + 10);
        let mut state = ParsingState::Normal;
        let mut id = Vec::with_capacity(20);
        for (i, &c) in self.text.iter().enumerate() {
            match (state, c) {
                (ParsingState::Normal, b'%') => state = ParsingState::Percent,
                (ParsingState::Normal, c) => s.push(c),
                (ParsingState::Percent, b'%') => {
                    state = ParsingState::Normal;
                    s.push(b'%');
                }
                (ParsingState::Percent, b'(') => {
                    state = ParsingState::OpenParen;
                    id.clear();
                }
                (ParsingState::Percent, _) => return Err(Error::InvalidCharacter(i)),
                (ParsingState::OpenParen, b')') => return Err(Error::InvalidCharacter(i)),
                (ParsingState::OpenParen, c) => {
                    state = ParsingState::Inside;
                    id.push(c);
                }
                (ParsingState::Inside, b')') => {
                    state = ParsingState::CloseParen;
                    s.extend(self.expand_text_pattern(&id, context)?.iter());
                }
                (ParsingState::Inside, c) => {
                    id.push(c);
                }
                (ParsingState::CloseParen, b'%') => state = ParsingState::Percent,
                (ParsingState::CloseParen, c) => {
                    state = ParsingState::Normal;
                    s.push(c);
                }
            }
        }
        Ok(s.into())
    }

    fn parse_byte_value(&self, data: &[u8], radix: u32) -> Result<Bytes, Error> {
        let s = std::str::from_utf8(data).map_err(|_| Error::InvalidRadixCharacter)?;
        let val = u8::from_str_radix(s, radix).map_err(|_| Error::InvalidRadixCharacter)?;
        Ok(Bytes::copy_from_slice(std::slice::from_ref(&val)))
    }

    fn expand_text_pattern(&self, id: &[u8], context: &TemplateContext) -> Result<Bytes, Error> {
        if let Some(val) = id.strip_prefix(b"senv:") {
            Ok(self.expand_env(val, context.senv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"cenv:") {
            Ok(self.expand_env(&val, context.cenv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"ctxsenv:") {
            Ok(self.expand_env(&val, context.ctxsenv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"senv?:") {
            Ok(self.has_entry(&val, context.senv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"cenv?:") {
            Ok(self.has_entry(&val, context.cenv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"ctxsenv?:") {
            Ok(self.has_entry(&val, context.ctxsenv.as_deref()))
        } else if let Some(val) = id.strip_prefix(b"sq:") {
            Ok(self.single_quote(&self.expand_text_pattern(&val, context)?))
        } else if let Some(val) = id.strip_prefix(b"byte:0x") {
            self.parse_byte_value(val, 16)
        } else if let Some(val) = id.strip_prefix(b"byte:0o") {
            self.parse_byte_value(val, 8)
        } else if let Some(val) = id.strip_prefix(b"byte:0b") {
            self.parse_byte_value(val, 2)
        } else if let Some(val) = id.strip_prefix(b"byte:") {
            self.parse_byte_value(val, 10)
        } else if id == b"nl" {
            Ok(Bytes::from(b"\n".as_slice()))
        } else {
            Err(Error::UnknownPattern(id.to_vec().into()))
        }
    }

    fn single_quote(&self, text: &[u8]) -> Bytes {
        let mut s: Vec<u8> = Vec::with_capacity(text.len() + 5);
        s.push(b'\'');
        for c in text.iter() {
            match c {
                b'\'' => s.extend(b"'\\''"),
                _ => s.push(*c),
            }
        }
        s.push(b'\'');
        s.into()
    }

    fn expand_env(&self, id: &[u8], map: Option<&BTreeMap<Bytes, Bytes>>) -> Bytes {
        match map {
            Some(map) => map.get(id).cloned().unwrap_or_else(Bytes::new),
            None => Bytes::new(),
        }
    }

    fn has_entry<T>(&self, id: &[u8], map: Option<&BTreeMap<Bytes, T>>) -> Bytes {
        match map {
            Some(map) => {
                if map.contains_key(id) {
                    "true".into()
                } else {
                    "false".into()
                }
            }
            None => "false".into(),
        }
    }
}

#[derive(Default, Clone)]
pub struct TemplateContext {
    pub senv: Option<Arc<BTreeMap<Bytes, Bytes>>>,
    pub cenv: Option<Arc<BTreeMap<Bytes, Bytes>>>,
    pub ctxsenv: Option<Arc<BTreeMap<Bytes, Bytes>>>,
    pub args: Option<Arc<[Bytes]>>,
    pub kind: Option<String>,
    pub extra: Option<serde_cbor::Value>,
}

impl<'a> From<&'a TemplateContext> for protocol::TemplateServerContextBody {
    fn from(ctx: &'a TemplateContext) -> protocol::TemplateServerContextBody {
        protocol::TemplateServerContextBody {
            senv: ctx.senv.as_deref().map(|x| (*x).clone()),
            cenv: ctx.cenv.as_deref().map(|x| (*x).clone()),
            ctxsenv: ctx.ctxsenv.as_deref().map(|x| (*x).clone()),
            args: ctx.args.as_deref().map(|x| x.to_vec()),
        }
    }
}

impl<'a> From<&'a mut TemplateContext> for protocol::TemplateServerContextBody {
    fn from(ctx: &'a mut TemplateContext) -> protocol::TemplateServerContextBody {
        protocol::TemplateServerContextBody::from(ctx as &TemplateContext)
    }
}

impl From<TemplateContext> for protocol::TemplateServerContextBody {
    fn from(ctx: TemplateContext) -> protocol::TemplateServerContextBody {
        protocol::TemplateServerContextBody::from(&ctx)
    }
}

impl<'a, T> From<&'a TemplateContext> for protocol::TemplateServerContextBodyWithBody<T> {
    fn from(ctx: &'a TemplateContext) -> protocol::TemplateServerContextBodyWithBody<T> {
        protocol::TemplateServerContextBodyWithBody {
            senv: ctx.senv.as_deref().map(|x| (*x).clone()),
            cenv: ctx.cenv.as_deref().map(|x| (*x).clone()),
            ctxsenv: ctx.ctxsenv.as_deref().map(|x| (*x).clone()),
            args: ctx.args.as_deref().map(|x| x.to_vec()),
            body: None,
        }
    }
}

impl<'a, T> From<&'a mut TemplateContext> for protocol::TemplateServerContextBodyWithBody<T> {
    fn from(ctx: &'a mut TemplateContext) -> protocol::TemplateServerContextBodyWithBody<T> {
        protocol::TemplateServerContextBodyWithBody::from(ctx as &TemplateContext)
    }
}

impl<T> From<TemplateContext> for protocol::TemplateServerContextBodyWithBody<T> {
    fn from(ctx: TemplateContext) -> protocol::TemplateServerContextBodyWithBody<T> {
        protocol::TemplateServerContextBodyWithBody::from(&ctx)
    }
}

impl From<protocol::TemplateServerContextBody> for TemplateContext {
    fn from(ctx: protocol::TemplateServerContextBody) -> TemplateContext {
        TemplateContext {
            senv: ctx.senv.map(Arc::new),
            cenv: ctx.cenv.map(Arc::new),
            ctxsenv: ctx.ctxsenv.map(Arc::new),
            args: ctx.args.map(|v| v.into_boxed_slice().into()),
            kind: None,
            extra: None,
        }
    }
}

impl<T> From<protocol::TemplateServerContextBodyWithBody<T>> for TemplateContext {
    fn from(ctx: protocol::TemplateServerContextBodyWithBody<T>) -> TemplateContext {
        TemplateContext {
            senv: ctx.senv.map(Arc::new),
            cenv: ctx.cenv.map(Arc::new),
            ctxsenv: ctx.ctxsenv.map(Arc::new),
            args: ctx.args.map(|v| v.into_boxed_slice().into()),
            kind: None,
            extra: None,
        }
    }
}

#[derive(Default)]
pub struct TemplateContextBuilder {
    ctx: TemplateContext,
}

#[allow(dead_code)]
impl TemplateContextBuilder {
    fn new() -> Self {
        Self {
            ctx: TemplateContext::default(),
        }
    }

    fn server_env(self, env: Option<Arc<BTreeMap<Bytes, Bytes>>>) -> Self {
        let mut s = self;
        s.ctx.senv = env;
        s
    }

    fn client_env(self, env: Option<Arc<BTreeMap<Bytes, Bytes>>>) -> Self {
        let mut s = self;
        s.ctx.cenv = env;
        s
    }

    fn context_server_env(self, env: Option<Arc<BTreeMap<Bytes, Bytes>>>) -> Self {
        let mut s = self;
        s.ctx.ctxsenv = env;
        s
    }

    fn args(self, args: Option<Arc<[Bytes]>>) -> Self {
        let mut s = self;
        s.ctx.args = args;
        s
    }

    fn build(self) -> TemplateContext {
        self.ctx
    }
}

#[cfg(test)]
mod tests {
    use super::{Template, TemplateContext};
    use std::sync::Arc;

    #[test]
    fn simple_expansion() {
        let cases = [
            ("Hello, world!", "Hello, world!"),
            ("Hello, %% world!", "Hello, % world!"),
        ];
        for (input, output) in &cases {
            let t = Template::new(input.as_bytes());
            let ctx = Default::default();
            assert_eq!(t.expand(&ctx).unwrap(), output);
        }
    }

    #[test]
    fn complex_expansion() {
        let mut ctx = TemplateContext::default();
        let senv = [("PATH", "/bin:/usr/bin"), ("HOME", "/nonexistent")]
            .iter()
            .cloned()
            .map(|(a, b)| (a.into(), b.into()))
            .collect();
        let cenv = [
            ("PATH", "/bin:/usr/bin:/usr/games"),
            ("HOME", "/somewhere-else"),
            ("TEXT", "This ' text has a '\\'' lot of weird characters"),
        ]
        .iter()
        .cloned()
        .map(|(a, b)| (a.into(), b.into()))
        .collect();
        let ctxenv = [("CREDENTIAL", "123456789")]
            .iter()
            .cloned()
            .map(|(a, b)| (a.into(), b.into()))
            .collect();
        ctx.senv = Some(Arc::new(senv));
        ctx.cenv = Some(Arc::new(cenv));
        ctx.ctxsenv = Some(Arc::new(ctxenv));
        let cases = [
            ("My path is '%(senv:PATH)'", "My path is '/bin:/usr/bin'"),
            (
                "Client's path is '%(cenv:PATH)'",
                "Client's path is '/bin:/usr/bin:/usr/games'",
            ),
            (
                "Nonexistent variable is empty: '%(cenv:RANDOM)'",
                "Nonexistent variable is empty: ''",
            ),
            (
                "Do I have a home? '%(senv?:HOME)'",
                "Do I have a home? 'true'",
            ),
            (
                "Do I have a random number? '%(cenv?:RANDOM)'",
                "Do I have a random number? 'false'",
            ),
            (
                "Do I have a credential? '%(ctxsenv?:CREDENTIAL)' '%(ctxsenv:CREDENTIAL)'",
                "Do I have a credential? 'true' '123456789'",
            ),
            // This testcase was produced with git rev-parse --sq-quote.
            (
                "Single quoting? %(sq:cenv:TEXT)",
                "Single quoting? 'This '\\'' text has a '\\''\\'\\'''\\'' lot of weird characters'",
            ),
            (
                "printf \"%%s/.local/share/remote-files\" \"$HOME\"",
                "printf \"%s/.local/share/remote-files\" \"$HOME\"",
            ),
            (
                "This string has a carriage%(byte:13)return, new%(nl)line, and some weird %(byte:0xc2)%(byte:0o251) %(byte:0xc2)%(byte:0b10100000) bytes.",
                "This string has a carriage\rreturn, new\nline, and some weird © \u{00a0} bytes.",
            ),
        ];
        for (input, output) in &cases {
            let t = Template::new(input.as_bytes());
            assert_eq!(t.expand(&ctx).unwrap(), output);
        }
    }
}
