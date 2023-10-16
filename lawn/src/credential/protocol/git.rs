use crate::credential::{
    Credential, CredentialParserError, CredentialRequest, FieldRequest, Location,
};
use bytes::Bytes;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
enum Extension {
    AuthType,
    Service,
}

type CredentialTitler = dyn (Fn(&Credential) -> Option<String>) + Send + Sync;
type BoxedCredentialTitler = Box<CredentialTitler>;

pub struct GitProtocolHandler {
    rdr: Arc<Mutex<dyn Read + Send>>,
    wrtr: Mutex<Option<Arc<Mutex<dyn Write + Send>>>>,
    extensions: Mutex<BTreeSet<Extension>>,
    service: Option<String>,
    kind: String,
    titler: BoxedCredentialTitler,
}

impl GitProtocolHandler {
    const BUFFER_SIZE: usize = 1024 * 1024;

    pub fn new(
        rdr: Arc<Mutex<dyn Read + Send>>,
        wrtr: Arc<Mutex<dyn Write + Send>>,
        service: Option<&str>,
        kind: Option<&str>,
        titler: Option<BoxedCredentialTitler>,
    ) -> Arc<Self> {
        Arc::new(Self {
            rdr,
            wrtr: Mutex::new(Some(wrtr)),
            extensions: Mutex::new(BTreeSet::new()),
            service: service.map(ToOwned::to_owned),
            kind: kind.unwrap_or("api").to_owned(),
            titler: titler.unwrap_or_else(|| {
                Box::new(|c: &Credential| {
                    Some(format!(
                        "Git: {}",
                        c.location().first().and_then(|loc| loc.as_url())?
                    ))
                })
            }),
        })
    }

    pub fn close_writer(self: Arc<Self>) {
        *self.wrtr.lock().unwrap() = None;
    }

    fn write_kv_request<T: Write>(
        v: &mut io::BufWriter<T>,
        key: &'static str,
        fr: &FieldRequest,
        multi: bool,
    ) -> Result<(), CredentialParserError> {
        match (fr, multi) {
            (FieldRequest::LiteralBytes(b), _) => Self::write_kv(v, key, &b)?,
            (FieldRequest::LiteralString(s), _) => Self::write_kv(v, key, s.as_bytes())?,
            (FieldRequest::Set(s), true) => {
                for item in s {
                    Self::write_kv_request(v, key, &item, false)?;
                }
            }
            (FieldRequest::Set(_), false) => {
                return Err(CredentialParserError::UnsatisfiableRequest(
                    key.into(),
                    "set".into(),
                ))
            }
            (FieldRequest::Sequence(s), true) => {
                for item in s {
                    Self::write_kv_request(v, key, &item, false)?;
                }
            }
            (FieldRequest::Sequence(_), false) => {
                return Err(CredentialParserError::UnsatisfiableRequest(
                    key.into(),
                    "sequence".into(),
                ))
            }
            (FieldRequest::Any, _) | (FieldRequest::None, _) => (),
        }
        Ok(())
    }

    pub fn send_fill_request(
        self: Arc<Self>,
        req: &CredentialRequest,
    ) -> Result<(), CredentialParserError> {
        let wrtr = self.wrtr.lock().unwrap();
        let wrtr = wrtr.as_ref().ok_or(CredentialParserError::NoSuchHandle)?;
        let mut wrtr = wrtr.lock().unwrap();
        let mut v = io::BufWriter::new(&mut *wrtr);
        let extensions = self.extensions.lock().unwrap();
        if extensions.contains(&Extension::AuthType) {
            Self::write_kv(
                &mut v,
                "capability",
                b"authtype@lawn.ns.crustytoothpaste.net",
            )?;
        }
        if extensions.contains(&Extension::Service) {
            Self::write_kv(
                &mut v,
                "capability",
                b"service@lawn.ns.crustytoothpaste.net",
            )?;
        }
        Self::write_kv_request(&mut v, "username", &req.username, false)?;
        Self::write_kv_request(&mut v, "protocol", &req.protocol, false)?;
        Self::write_kv_request(&mut v, "host", &req.host, false)?;
        Self::write_kv_request(&mut v, "path", &req.path, false)?;
        if extensions.contains(&Extension::AuthType) {
            Self::write_kv_request(&mut v, "authtype", &req.authtype, false)?;
        }
        if extensions.contains(&Extension::Service) {
            Self::write_kv_request(&mut v, "service", &req.service, false)?;
        }
        if let Some(wwwauth) = req.extra.get("wwwauth@git.ns.crustytoothpaste.net") {
            Self::write_kv_request(&mut v, "wwwauth[]", &wwwauth, true)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn parse_fill_request(self: Arc<Self>) -> Result<CredentialRequest, CredentialParserError> {
        let buf = self.clone().read_buf_to_max()?;
        let mut req = CredentialRequest::new();
        for line in buf.split(|x| *x == b'\n') {
            let mut pair = line.splitn(2, |x| *x == b'=');
            match (pair.next(), pair.next()) {
                (Some(b"protocol"), Some(val)) => {
                    req.protocol = FieldRequest::LiteralBytes(Bytes::from(val.to_vec()))
                }
                (Some(b"host"), Some(val)) => {
                    req.host = FieldRequest::LiteralBytes(Bytes::from(val.to_vec()))
                }
                (Some(b"path"), Some(val)) => {
                    req.path = FieldRequest::LiteralBytes(Bytes::from(val.to_vec()))
                }
                (Some(b"username"), Some(val)) => {
                    req.username = FieldRequest::LiteralBytes(Bytes::from(val.to_vec()))
                }
                (Some(b"wwwauth[]"), Some(val)) => {
                    if let FieldRequest::Sequence(v) = req
                        .extra
                        .entry(String::from("wwwauth@git.ns.crustytoothpaste.net"))
                        .or_insert_with(|| FieldRequest::Sequence(Vec::new()))
                    {
                        v.push(FieldRequest::LiteralBytes(Bytes::from(val.to_vec())));
                    }
                }
                (Some(b"capability"), Some(b"authtype@lawn.ns.crustytoothpaste.net")) => {
                    let mut extensions = self.extensions.lock().unwrap();
                    extensions.insert(Extension::AuthType);
                }
                (Some(b"capability"), Some(b"service@lawn.ns.crustytoothpaste.net")) => {
                    let mut extensions = self.extensions.lock().unwrap();
                    extensions.insert(Extension::Service);
                }
                (Some(b"service"), Some(val)) => {
                    let extensions = self.extensions.lock().unwrap();
                    if extensions.contains(&Extension::Service) {
                        req.service = FieldRequest::LiteralBytes(Bytes::from(val.to_vec()));
                    }
                }
                (Some(b""), None) => (),
                (Some(_), None) => {
                    return Err(CredentialParserError::InvalidSerialization(Cow::Borrowed(
                        "equals sign required",
                    )))
                }
                _ => (),
            }
        }
        Ok(req)
    }

    fn write_kv<T: Write>(v: &mut io::BufWriter<T>, key: &str, value: &[u8]) -> io::Result<()> {
        v.write_all(key.as_bytes())?;
        v.write_all(b"=")?;
        v.write_all(value)?;
        v.write_all(b"\n")?;
        Ok(())
    }

    pub fn parse_fill_response(
        self: Arc<Self>,
    ) -> Result<Option<Credential>, CredentialParserError> {
        self.parse_approve_reject_request(true)
    }

    pub fn send_fill_response(self: Arc<Self>, cred: Option<&Credential>) -> io::Result<()> {
        let cred = match cred {
            Some(c) => c,
            None => return Ok(()),
        };
        let wrtr = self.wrtr.lock().unwrap();
        let wrtr = wrtr
            .as_ref()
            .ok_or(io::Error::from_raw_os_error(libc::EBADF))?;
        let mut wrtr = wrtr.lock().unwrap();
        let mut v = io::BufWriter::new(&mut *wrtr);
        let extensions = self.extensions.lock().unwrap();
        if extensions.contains(&Extension::AuthType) {
            Self::write_kv(
                &mut v,
                "capability",
                b"authtype@lawn.ns.crustytoothpaste.net",
            )?;
        }
        if extensions.contains(&Extension::Service) {
            Self::write_kv(
                &mut v,
                "capability",
                b"service@lawn.ns.crustytoothpaste.net",
            )?;
        }
        if let Some(val) = &cred.username {
            Self::write_kv(&mut v, "username", val)?;
        }
        Self::write_kv(&mut v, "password", &cred.secret)?;
        if extensions.contains(&Extension::AuthType) {
            if let Some(val) = &cred.authtype {
                Self::write_kv(&mut v, "authtype", val.as_bytes())?;
            }
        }
        if extensions.contains(&Extension::Service) {
            if let Some(val) = &cred.service {
                Self::write_kv(&mut v, "service", val.as_bytes())?;
            }
        }
        if let Some(loc) = &cred.location.first() {
            if let Some(val) = &loc.protocol {
                Self::write_kv(&mut v, "protocol", val.as_bytes())?;
            }
            if let Some(val) = &loc.host {
                Self::write_kv(&mut v, "host", val.as_bytes())?;
            }
            if let Some(val) = &loc.path {
                Self::write_kv(&mut v, "path", val.as_bytes())?;
            }
        }
        Self::write_kv(&mut v, "id", &cred.id)?;
        Ok(())
    }

    pub fn parse_approve_reject_request(
        self: Arc<Self>,
        need_secret: bool,
    ) -> Result<Option<Credential>, CredentialParserError> {
        let buf = self.clone().read_buf_to_max()?;
        let mut cred = Credential::new();
        let mut loc = Location::new();
        let mut has_secret = false;
        let mut id = None;
        for line in buf.split(|x| *x == b'\n') {
            let mut pair = line.splitn(2, |x| *x == b'=');
            match (pair.next(), pair.next()) {
                (Some(b"protocol"), Some(val)) => {
                    if let Ok(s) = std::str::from_utf8(val) {
                        loc.protocol = Some(s.into());
                    }
                }
                (Some(b"host"), Some(val)) => {
                    if let Ok(s) = std::str::from_utf8(val) {
                        loc.host = Some(s.into());
                    }
                }
                (Some(b"path"), Some(val)) => {
                    if let Ok(s) = std::str::from_utf8(val) {
                        loc.path = Some(s.into());
                    }
                }
                (Some(b"username"), Some(val)) => {
                    cred.username = Some(Bytes::from(val.to_vec()));
                }
                (Some(b"password"), Some(val)) => {
                    cred.secret = Bytes::from(val.to_vec());
                    has_secret = true;
                }
                (Some(b"authtype"), Some(val)) => {
                    if let Ok(s) = std::str::from_utf8(val) {
                        cred.authtype = Some(s.into());
                    }
                }
                (Some(b"id"), Some(val)) => {
                    id = Some(Bytes::copy_from_slice(val));
                }
                (Some(b"capability"), Some(b"authtype@lawn.ns.crustytoothpaste.net")) => {
                    let mut extensions = self.extensions.lock().unwrap();
                    extensions.insert(Extension::AuthType);
                }
                (Some(b"capability"), Some(b"service@lawn.ns.crustytoothpaste.net")) => {
                    let mut extensions = self.extensions.lock().unwrap();
                    extensions.insert(Extension::Service);
                }
                (Some(b""), None) => (),
                (Some(_), None) => {
                    return Err(CredentialParserError::InvalidSerialization(Cow::Borrowed(
                        "equals sign required",
                    )))
                }
                _ => (),
            }
        }
        if loc.has_contents() {
            cred.location = vec![loc];
        }
        if cred.service.is_none() {
            cred.service = self.service.clone();
        }
        cred.kind = self.kind.clone();
        cred.title = (*self.titler)(&cred);
        cred.id = id.unwrap_or_else(|| cred.generate_id());
        if has_secret || !need_secret {
            Ok(Some(cred))
        } else {
            Ok(None)
        }
    }

    pub fn send_approve_reject_request(self: Arc<Self>, credential: &Credential) -> io::Result<()> {
        self.send_fill_response(Some(credential))
    }

    fn read_buf_to_max(self: Arc<Self>) -> Result<Vec<u8>, CredentialParserError> {
        let mut rdr = self.rdr.lock().unwrap();
        let mut vec = vec![0u8; Self::BUFFER_SIZE];
        let mut off = 0;
        while off < vec.len() {
            match rdr.read(&mut vec[off..]) {
                Ok(0) => {
                    vec.truncate(off);
                    break;
                }
                Ok(n) => off += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(CredentialParserError::IOError(e)),
            }
        }
        if off == Self::BUFFER_SIZE {
            return Err(CredentialParserError::DataTooLarge);
        }
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::{Credential, CredentialRequest, FieldRequest, GitProtocolHandler, Location};
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_parse_fill_simple() {
        let input = br"protocol=https
host=example.com
";
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        let req = handler.parse_fill_request().unwrap();
        assert_eq!(req.username, FieldRequest::Any);
        assert_eq!(req.authtype, FieldRequest::Any);
        assert_eq!(
            req.protocol,
            FieldRequest::LiteralBytes(Bytes::from(b"https" as &[u8]))
        );
        assert_eq!(
            req.host,
            FieldRequest::LiteralBytes(Bytes::from(b"example.com" as &[u8]))
        );
        assert_eq!(req.path, FieldRequest::Any);
        assert_eq!(req.service, FieldRequest::Any);
        assert!(req.extra.is_empty());
    }

    #[test]
    fn test_parse_fill_complex() {
        let input = br"protocol=https
host=example.com
username=cookie-monster
path=/foo/bar/baz.git
";
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        let req = handler.parse_fill_request().unwrap();
        assert_eq!(
            req.username,
            FieldRequest::LiteralBytes(Bytes::from(b"cookie-monster" as &[u8]))
        );
        assert_eq!(req.authtype, FieldRequest::Any);
        assert_eq!(
            req.protocol,
            FieldRequest::LiteralBytes(Bytes::from(b"https" as &[u8]))
        );
        assert_eq!(
            req.host,
            FieldRequest::LiteralBytes(Bytes::from(b"example.com" as &[u8]))
        );
        assert_eq!(
            req.path,
            FieldRequest::LiteralBytes(Bytes::from(b"/foo/bar/baz.git" as &[u8]))
        );
        assert_eq!(req.service, FieldRequest::Any);
        assert!(req.extra.is_empty());
    }

    #[test]
    fn test_parse_fill_extensions() {
        let input = br#"capability=authtype@lawn.ns.crustytoothpaste.net
capability=service@lawn.ns.crustytoothpaste.net
protocol=https
host=example.com
username=cookie-monster
path=/foo/bar/baz.git
wwwauth[]=Basic realm="example.com"
wwwauth[]=Negotiate
"#;
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        let req = handler.parse_fill_request().unwrap();
        assert_eq!(
            req.username,
            FieldRequest::LiteralBytes(Bytes::from(b"cookie-monster" as &[u8]))
        );
        assert_eq!(req.authtype, FieldRequest::Any);
        assert_eq!(
            req.protocol,
            FieldRequest::LiteralBytes(Bytes::from(b"https" as &[u8]))
        );
        assert_eq!(
            req.host,
            FieldRequest::LiteralBytes(Bytes::from(b"example.com" as &[u8]))
        );
        assert_eq!(
            req.path,
            FieldRequest::LiteralBytes(Bytes::from(b"/foo/bar/baz.git" as &[u8]))
        );
        assert_eq!(req.service, FieldRequest::Any,);
        assert_eq!(req.extra.len(), 1);
        assert_eq!(
            req.extra
                .get("wwwauth@git.ns.crustytoothpaste.net")
                .unwrap(),
            &FieldRequest::Sequence(vec![
                FieldRequest::LiteralBytes(Bytes::from(br#"Basic realm="example.com""# as &[u8])),
                FieldRequest::LiteralBytes(Bytes::from(b"Negotiate" as &[u8]))
            ])
        );
    }

    #[test]
    fn test_send_fill_simple() {
        let req = CredentialRequest {
            protocol: FieldRequest::LiteralBytes(Bytes::from(b"https" as &[u8])),
            host: FieldRequest::LiteralBytes(Bytes::from(b"example.com" as &[u8])),
            kind: FieldRequest::Any,
            username: FieldRequest::Any,
            authtype: FieldRequest::Any,
            title: FieldRequest::Any,
            description: FieldRequest::Any,
            service: FieldRequest::Any,
            id: FieldRequest::Any,
            path: FieldRequest::Any,
            extra: Default::default(),
        };
        let rdr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr.clone(), Some("git"), None, None);
        handler.send_fill_request(&req).unwrap();
        let wrtr = std::mem::take(&mut *wrtr.lock().unwrap());
        assert_eq!(
            wrtr.into_inner(),
            br#"protocol=https
host=example.com
"#
        );
    }

    #[test]
    fn test_parse_approve_simple() {
        let input = br"protocol=https
host=example.com
username=cookie-monster
password=abc123
path=/foo/bar/baz.git
";
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        let req = handler.parse_approve_reject_request(true).unwrap().unwrap();
        let loc = &req.location()[0];
        assert_eq!(loc.protocol().unwrap(), "https");
        assert_eq!(loc.host().unwrap(), "example.com");
        assert_eq!(req.username().unwrap(), b"cookie-monster" as &[u8]);
        assert_eq!(req.secret(), b"abc123" as &[u8]);
        assert_eq!(loc.path().unwrap(), "/foo/bar/baz.git");
    }

    #[test]
    fn test_parse_approve_no_cred() {
        let input = br"protocol=https
host=example.com
username=cookie-monster
path=/foo/bar/baz.git
";
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        assert!(handler
            .parse_approve_reject_request(true)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_parse_approve_no_cred_no_secret() {
        let input = br"protocol=https
host=example.com
username=cookie-monster
path=/foo/bar/baz.git
";
        let rdr = Arc::new(Mutex::new(Cursor::new(input)));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr, Some("git"), None, None);
        let cred = handler
            .parse_approve_reject_request(false)
            .unwrap()
            .unwrap();
        let loc = &cred.location()[0];
        assert_eq!(loc.protocol().unwrap(), "https");
        assert_eq!(loc.host().unwrap(), "example.com");
        assert_eq!(cred.username().unwrap(), b"cookie-monster" as &[u8]);
        assert_eq!(loc.path().unwrap(), "/foo/bar/baz.git");
    }

    #[test]
    fn test_send_fill_cred() {
        let input = Credential {
            username: Some("cookie-monster".into()),
            secret: Bytes::from(b"very-secret-credential" as &[u8]),
            authtype: None,
            kind: "api".into(),
            location: vec![Location {
                protocol: Some("https".into()),
                host: Some("example.com".into()),
                port: None,
                path: Some("/foo/bar/baz.git".into()),
            }],
            service: None,
            title: None,
            description: None,
            extra: BTreeMap::new(),
            id: Bytes::from(b"abc123" as &[u8]),
        };
        let rdr = Arc::new(Mutex::new(Cursor::new(b"")));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr.clone(), Some("git"), None, None);
        handler.send_fill_response(Some(&input)).unwrap();
        let wrtr = std::mem::take(&mut *wrtr.lock().unwrap());
        assert_eq!(
            wrtr.into_inner(),
            br#"username=cookie-monster
password=very-secret-credential
protocol=https
host=example.com
path=/foo/bar/baz.git
id=abc123
"#
        );
    }

    #[test]
    fn test_send_fill_no_cred() {
        let rdr = Arc::new(Mutex::new(Cursor::new(b"")));
        let wrtr = Arc::new(Mutex::new(Cursor::new(Vec::new())));
        let handler = GitProtocolHandler::new(rdr, wrtr.clone(), Some("git"), None, None);
        handler.send_fill_response(None).unwrap();
        let wrtr = std::mem::take(&mut *wrtr.lock().unwrap());
        assert_eq!(wrtr.into_inner(), b"");
    }
}
