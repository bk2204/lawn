use crate::backend::{
    AttributeFlags, Attributes, Backend, Handle, OpenFlags, ProtocolExtensions, ProtocolResponse,
    ProtocolTag, ProtocolVersion, SFTPError, SFTPErrorKind, Tag,
};
use lawn_constants::logger::Logger;
use lawn_constants::Error;
use lawn_fs::backend as fsbackend;
use num_traits::FromPrimitive;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryInto;
use std::io;
use std::marker::Unpin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub enum ServerError {
    InvalidSize,
    IOError(io::Error),
}

impl From<io::Error> for ServerError {
    fn from(e: io::Error) -> ServerError {
        ServerError::IOError(e)
    }
}

pub struct Metadata {
    pub(crate) ver: ProtocolVersion,
    pub(crate) data: Arc<RwLock<ProtocolData>>,
    pub(crate) tag: Tag,
    pub(crate) msg: ProtocolTag,
}

impl Metadata {
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.ver
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub(crate) fn protocol_data(&self) -> Arc<RwLock<ProtocolData>> {
        self.data.clone()
    }
}

impl<'a> From<&'a Metadata> for fsbackend::Metadata<'a> {
    fn from(meta: &'a Metadata) -> fsbackend::Metadata<'a> {
        fsbackend::Metadata::new(
            fsbackend::Tag::new(meta.tag.0 as u64),
            meta.msg as u64,
            fsbackend::ProtocolType::SFTP(fsbackend::SFTPType::V3, &[]),
            None,
            true,
        )
    }
}

pub(crate) struct ProtocolData {
    pub(crate) ver: ProtocolVersion,
    pub(crate) extensions: BTreeSet<ProtocolExtensions>,
    pub(crate) max_size: usize,
}

struct Deserializer<'a> {
    data: &'a [u8],
    off: AtomicUsize,
}

#[allow(dead_code)]
impl<'a> Deserializer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            off: AtomicUsize::new(0),
        }
    }

    fn offset(&self) -> usize {
        self.off.load(Ordering::Acquire)
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn read_u8(&self) -> Result<u8, Error> {
        let off = self.off.fetch_add(1, Ordering::AcqRel);
        if off + 1 > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(self.data[off])
    }

    fn read_u16(&self) -> Result<u16, Error> {
        let off = self.off.fetch_add(2, Ordering::AcqRel);
        if off + 2 > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(u16::from_be_bytes(
            self.data[off..off + 2].try_into().unwrap(),
        ))
    }

    fn read_u32(&self) -> Result<u32, Error> {
        let off = self.off.fetch_add(4, Ordering::AcqRel);
        if off + 4 > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(u32::from_be_bytes(
            self.data[off..off + 4].try_into().unwrap(),
        ))
    }

    fn read_u64(&self) -> Result<u64, Error> {
        let off = self.off.fetch_add(8, Ordering::AcqRel);
        if off + 8 > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(u64::from_be_bytes(
            self.data[off..off + 8].try_into().unwrap(),
        ))
    }

    fn read_tag(&self) -> Result<Tag, Error> {
        let data = self.read_u32()?;
        Ok(Tag(data))
    }

    fn read_string(&self) -> Result<&[u8], Error> {
        let len = self.read_u32()? as usize;
        let off = self.off.fetch_add(len, Ordering::AcqRel);
        if off + len > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(&self.data[off..off + len])
    }

    fn read_handle(&self) -> Result<Handle, Error> {
        let len = self.read_u32()? as usize;
        let off = self.off.fetch_add(len, Ordering::AcqRel);
        if off + len > self.data.len() || len != 4 {
            return Err(Error::EBADMSG);
        }
        Ok(Handle(u32::from_be_bytes(
            self.data[off..off + len].try_into().unwrap(),
        )))
    }

    fn read_data(&self, len: usize) -> Result<&[u8], Error> {
        let off = self.off.fetch_add(len, Ordering::AcqRel);
        if off + len > self.data.len() {
            return Err(Error::EBADMSG);
        }
        Ok(&self.data[off..off + len])
    }

    fn read_attrs(&self) -> Result<Attributes, Error> {
        let flags = self.read_u32()?;
        let flags = AttributeFlags::from_bits(flags).ok_or(Error::EOPNOTSUPP)?;
        let mut attrs = Attributes::default();
        if flags.contains(AttributeFlags::SIZE) {
            attrs.size = Some(self.read_u64()?);
        }
        if flags.contains(AttributeFlags::UIDGID) {
            attrs.uid = Some(self.read_u32()?);
            attrs.gid = Some(self.read_u32()?);
        }
        if flags.contains(AttributeFlags::PERMISSIONS) {
            attrs.permissions = Some(self.read_u32()?);
        }
        if flags.contains(AttributeFlags::ACMODTIME) {
            attrs.atime = Some(self.read_u32()?);
            attrs.mtime = Some(self.read_u32()?);
        }
        if flags.contains(AttributeFlags::EXTENDED) {
            let pairs = self.read_u32()?;
            let mut extended = BTreeMap::new();
            for _ in 0..pairs {
                extended.insert(
                    self.read_string()?.to_owned(),
                    self.read_string()?.to_owned(),
                );
            }
            attrs.extended = extended;
        }
        Ok(attrs)
    }
}

pub(crate) struct Serializer {
    data: Vec<u8>,
}

#[allow(dead_code)]
impl Serializer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.data
    }

    pub fn write_u8(&mut self, data: u8) {
        self.data.extend(&[data]);
    }

    pub fn write_u16(&mut self, data: u16) {
        self.data.extend(&data.to_be_bytes());
    }

    pub fn write_u32(&mut self, data: u32) {
        self.data.extend(&data.to_be_bytes());
    }

    pub fn write_u64(&mut self, data: u64) {
        self.data.extend(&data.to_be_bytes());
    }

    pub fn write_string(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > u32::MAX as usize {
            return Err(Error::ENOMEM);
        }
        self.write_u32(data.len() as u32);
        self.data.extend(data.iter());
        Ok(())
    }

    pub fn write_handle(&mut self, data: Handle) {
        let data = data.0.to_be_bytes();
        let _ = self.write_string(&data);
    }

    pub fn write_tag(&mut self, tag: Tag) {
        self.write_u32(tag.0);
    }

    pub fn write_data(&mut self, data: &[u8]) {
        self.data.extend(data);
    }

    pub fn write_response<T: ProtocolResponse>(&mut self, data: &T) -> Result<(), Error> {
        ProtocolResponse::serialize(data, self)
    }
}

pub struct Server<R: AsyncReadExt + Unpin + Send + Sync, W: AsyncWriteExt + Unpin + Send + Sync> {
    backend: Arc<Backend>,
    rd: R,
    wr: W,
    pdata: Arc<RwLock<ProtocolData>>,
    logger: Arc<dyn Logger + Send + Sync>,
}

impl<R: AsyncReadExt + Unpin + Send + Sync, W: AsyncWriteExt + Unpin + Send + Sync> Server<R, W> {
    /// The largest buffer size we'll allocate.
    ///
    /// This exists to prevent DoS attacks from consuming excessive memory.
    const MAX_BUFFER_SIZE: usize = 1024 * 1024;

    const SIZE_SIZE: usize = 4;
    const TAG_SIZE: usize = 1;
    const ID_SIZE: usize = 4;
    const STRING_HEADER_SIZE: usize = 4;
    const HEADER_SIZE: usize = Self::SIZE_SIZE + Self::TAG_SIZE;

    pub fn new(
        logger: Arc<dyn Logger + Send + Sync>,
        backend: Backend,
        rd: R,
        wr: W,
    ) -> Server<R, W> {
        Self {
            logger,
            backend: Arc::new(backend),
            rd,
            wr,
            pdata: Arc::new(RwLock::new(ProtocolData {
                ver: ProtocolVersion::V3,
                extensions: BTreeSet::new(),
                max_size: Self::MAX_BUFFER_SIZE + Self::HEADER_SIZE,
            })),
        }
    }

    pub fn shutdown(&self) {}

    #[allow(clippy::let_unit_value)]
    fn process_message(
        logger: Arc<dyn Logger + Send + Sync>,
        backend: Arc<Backend>,
        pdata: Arc<RwLock<ProtocolData>>,
        msg: ProtocolTag,
        tag: Tag,
        buf: &[u8],
    ) -> Result<(ProtocolTag, Vec<u8>), Error> {
        let meta = Metadata {
            ver: pdata.read().unwrap().ver,
            data: pdata.clone(),
            tag,
            msg,
        };
        let d = Deserializer::new(buf);
        let mut s = Serializer::new();
        trace!(
            logger,
            "SFTP: message {:?} {:?} {:08x}",
            msg,
            meta.ver,
            tag.0,
        );
        match msg {
            ProtocolTag::Init => {
                // We've read the tag, but in this message, there is no tag, only a version, so we
                // convert it.
                let version = tag.0;
                let mut map = BTreeMap::new();
                while d.offset() < d.len() {
                    let key = d.read_string()?;
                    let val = d.read_string()?;
                    map.insert(key, val);
                }
                let (ver, extensions) = backend.init(version, &map)?;
                s.write_u32(ver as u32);
                for (k, v) in extensions.iter().filter_map(|e| e.to_tuple()) {
                    s.write_string(k)?;
                    s.write_string(v)?;
                }
                let mut g = pdata.write().unwrap();
                g.ver = ver;
                g.extensions = extensions;
                Ok((ProtocolTag::Version, s.into_inner()))
            }
            ProtocolTag::Open => {
                let filename = d.read_string()?;
                let flags = OpenFlags::from_bits(d.read_u32()?).ok_or(Error::EBADMSG)?;
                let attrs = d.read_attrs()?;
                let handle = backend.open(&meta, filename, flags, &attrs)?;
                s.write_handle(handle);
                Ok((ProtocolTag::Handle, s.into_inner()))
            }
            ProtocolTag::Close => {
                let resp = backend.close(&meta, d.read_handle()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Read => {
                let handle = d.read_handle()?;
                let offset = d.read_u64()?;
                let len = d.read_u32()? as usize;
                let max_size = pdata.read().unwrap().max_size;
                if len > max_size - (Self::HEADER_SIZE + Self::ID_SIZE + Self::STRING_HEADER_SIZE) {
                    return Err(Error::EINVAL);
                }
                let mut vec = vec![0u8; len];
                let resp = backend.read(&meta, handle, offset, &mut vec)?;
                if resp == 0 {
                    s.write_response(&SFTPError::new(SFTPErrorKind::EOF, "EOF"))?;
                    return Ok((ProtocolTag::Status, s.into_inner()));
                }
                vec.truncate(resp as usize);
                s.write_string(&vec)?;
                Ok((ProtocolTag::Data, s.into_inner()))
            }
            ProtocolTag::Write => {
                let resp =
                    backend.write(&meta, d.read_handle()?, d.read_u64()?, d.read_string()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Remove => {
                let resp = backend.remove(&meta, d.read_string()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Rename => {
                let resp = backend.rename(&meta, d.read_string()?, d.read_string()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Mkdir => {
                let path = d.read_string()?;
                let attrs = d.read_attrs()?;
                let resp = backend.mkdir(&meta, path, &attrs)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Rmdir => {
                let resp = backend.rmdir(&meta, d.read_string()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Opendir => {
                let resp = backend.opendir(&meta, d.read_string()?)?;
                s.write_handle(resp);
                Ok((ProtocolTag::Handle, s.into_inner()))
            }
            ProtocolTag::Readdir => {
                let resp = backend.readdir(&meta, d.read_handle()?)?;
                if resp.is_empty() {
                    s.write_response(&SFTPError::new(SFTPErrorKind::EOF, "EOF"))?;
                    return Ok((ProtocolTag::Status, s.into_inner()));
                }
                s.write_u32(resp.len() as u32);
                for entry in resp {
                    entry.serialize(&mut s)?;
                }
                Ok((ProtocolTag::Name, s.into_inner()))
            }
            ProtocolTag::Stat => {
                let attrs = backend.stat(&meta, d.read_string()?)?;
                attrs.serialize(&mut s)?;
                Ok((ProtocolTag::Attrs, s.into_inner()))
            }
            ProtocolTag::Lstat => {
                let attrs = backend.lstat(&meta, d.read_string()?)?;
                attrs.serialize(&mut s)?;
                Ok((ProtocolTag::Attrs, s.into_inner()))
            }
            ProtocolTag::Fstat => {
                let attrs = backend.fstat(&meta, d.read_handle()?)?;
                attrs.serialize(&mut s)?;
                Ok((ProtocolTag::Attrs, s.into_inner()))
            }
            ProtocolTag::Setstat => {
                let path = d.read_string()?;
                let attrs = d.read_attrs()?;
                let resp = backend.setstat(&meta, path, &attrs)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Fsetstat => {
                let handle = d.read_handle()?;
                let attrs = d.read_attrs()?;
                let resp = backend.fsetstat(&meta, handle, &attrs)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Readlink => {
                let resp = backend.readlink(&meta, d.read_string()?)?;
                s.write_u32(1);
                s.write_response(&resp)?;
                Ok((ProtocolTag::Name, s.into_inner()))
            }
            ProtocolTag::Symlink => {
                let resp = backend.symlink(&meta, d.read_string()?, d.read_string()?)?;
                s.write_response(&resp)?;
                Ok((ProtocolTag::Status, s.into_inner()))
            }
            ProtocolTag::Realpath => {
                let resp = backend.realpath(&meta, d.read_string()?)?;
                s.write_u32(1);
                s.write_response(&resp)?;
                Ok((ProtocolTag::Name, s.into_inner()))
            }
            ProtocolTag::Extended => {
                let kind = d.read_string()?;
                let g = pdata.read().unwrap();
                match kind {
                    b"fsync@openssh.com"
                        if g.extensions.contains(&ProtocolExtensions::OpenSSHFsyncV1) =>
                    {
                        let resp = backend.fsync(&meta, d.read_handle()?)?;
                        s.write_response(&resp)?;
                        Ok((ProtocolTag::Status, s.into_inner()))
                    }
                    b"hardlink@openssh.com"
                        if g.extensions
                            .contains(&ProtocolExtensions::OpenSSHHardlinkV1) =>
                    {
                        let resp = backend.link(&meta, d.read_string()?, d.read_string()?)?;
                        s.write_response(&resp)?;
                        Ok((ProtocolTag::Status, s.into_inner()))
                    }
                    b"posix-rename@openssh.com"
                        if g.extensions
                            .contains(&ProtocolExtensions::OpenSSHPosixRenameV1) =>
                    {
                        let resp =
                            backend.posix_rename(&meta, d.read_string()?, d.read_string()?)?;
                        s.write_response(&resp)?;
                        Ok((ProtocolTag::Status, s.into_inner()))
                    }
                    _ => Err(Error::EOPNOTSUPP),
                }
            }
            _ => Err(Error::EOPNOTSUPP),
        }
    }

    async fn send_message(
        &mut self,
        msg: u8,
        tag: Option<Tag>,
        body: &[u8],
    ) -> Result<(), ServerError> {
        let len = 1u32 + body.len() as u32 + tag.map(|_| 4).unwrap_or_default();
        if let Some(tag) = tag {
            trace!(
                self.logger,
                "SFTP: sending response msg {:02x} len {:08x} tag {:08x}",
                msg,
                len,
                tag.0
            );
        } else {
            trace!(
                self.logger,
                "SFTP: sending response msg {:02x} len {:08x} tag None",
                msg,
                len
            );
        }
        let len = len.to_be_bytes();
        let prefix = [len[0], len[1], len[2], len[3], msg];
        self.wr.write_all(&prefix).await?;
        if let Some(tag) = tag {
            let tagb = tag.0.to_be_bytes();
            self.wr.write_all(&tagb).await?;
        }
        self.wr.write_all(body).await?;
        Ok(())
    }

    async fn send_error<T: Into<SFTPError> + std::fmt::Debug>(
        &mut self,
        msg: ProtocolTag,
        tag: Tag,
        err: T,
    ) -> Result<(), ServerError> {
        trace!(self.logger, "SFTP: sending error {:?} {:?}", msg, err);
        let e: SFTPError = err.into();
        trace!(self.logger, "SFTP: converted error to {:?} {:?}", msg, e);
        let mut s = Serializer::new();
        let tag = if msg == ProtocolTag::Init {
            Tag(0)
        } else {
            tag
        };
        let _ = s.write_response(&e);
        let body = s.into_inner();
        self.send_message(ProtocolTag::Status as u8, Some(tag), &body)
            .await
    }

    async fn parse_message(&mut self, buf: &[u8; 9]) -> Result<(), ServerError> {
        let size = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let msg = ProtocolTag::from_u8(buf[4]);
        let tag = Tag(u32::from_be_bytes(buf[5..9].try_into().unwrap()));
        // The value we use here is 5 because the length does not include its own length.
        if size < 5 || size as usize > self.pdata.read().unwrap().max_size {
            error!(self.logger, "read unexpected size {:08x}", size);
            return Err(ServerError::InvalidSize);
        }
        let mut v = vec![0u8; (size as usize) - 5];
        self.rd.read_exact(&mut v).await?;
        let msg = match msg {
            Some(msg) => {
                trace!(
                    self.logger,
                    "SFTP: message {:?} ({:02x}) size {:08x} tag {:08x}",
                    msg,
                    msg as u8,
                    size,
                    tag.0,
                );
                msg
            }
            None => {
                trace!(
                    self.logger,
                    "SFTP: unknown message {:02x} size {:08x} tag {:08x}",
                    buf[4],
                    size,
                    tag.0,
                );
                self.send_error(ProtocolTag::Status, tag, Error::EOPNOTSUPP)
                    .await?;
                return Ok(());
            }
        };
        let logger = self.logger.clone();
        let backend = self.backend.clone();
        let pdata = self.pdata.clone();
        match tokio::task::spawn_blocking(move || {
            Self::process_message(logger, backend, pdata, msg, tag, &v)
        })
        .await
        .unwrap()
        {
            Ok((rmsg, body)) => {
                trace!(
                    self.logger,
                    "SFTP: message {:?} ok, sending response of type {:?}",
                    msg,
                    rmsg
                );
                let tag = if rmsg == ProtocolTag::Version {
                    None
                } else {
                    Some(tag)
                };
                self.send_message(rmsg as u8, tag, &body).await?;
                Ok(())
            }
            Err(e) => self.send_error(msg, tag, e).await,
        }
    }

    pub async fn run(&mut self) -> Result<(), ServerError> {
        trace!(self.logger, "SFTP: starting server");
        loop {
            let mut buf = [0u8; 9];
            let res = self.rd.read(&mut buf).await;
            trace!(self.logger, "SFTP: read data");
            match res {
                Ok(9) => {
                    trace!(self.logger, "SFTP: message header received");
                    self.parse_message(&buf).await?;
                }
                Ok(0) => return Ok(()),
                Ok(n) => {
                    trace!(self.logger, "SFTP: partial message header received");
                    self.rd.read_exact(&mut buf[n..9]).await?;
                    self.parse_message(&buf).await?;
                }
                Err(e) => {
                    trace!(self.logger, "SFTP: got error {} on read", e);
                    return Err(ServerError::IOError(e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Deserializer;

    #[test]
    fn deserialize_attributes() {
        let cases: &[(
            &str,
            &[u8],
            Option<u64>,
            Option<u32>,
            Option<u32>,
            Option<u32>,
            Option<u32>,
            Option<u32>,
        )] = &[(
            "single permissions 0755",
            b"\x00\x00\x00\x04\x00\x00\x01\xed",
            None,
            None,
            None,
            Some(0o755),
            None,
            None,
        )];
        for (desc, bytes, size, uid, gid, permissions, atime, mtime) in cases {
            let d = Deserializer::new(*bytes);
            let attrs = d.read_attrs().unwrap();
            assert_eq!(*size, attrs.size, "size: {}", desc);
            assert_eq!(*uid, attrs.uid, "uid: {}", desc);
            assert_eq!(*gid, attrs.gid, "gid: {}", desc);
            assert_eq!(*permissions, attrs.permissions, "permissions: {}", desc);
            assert_eq!(*atime, attrs.atime, "atime: {}", desc);
            assert_eq!(*mtime, attrs.mtime, "mtime: {}", desc);
        }
    }
}
