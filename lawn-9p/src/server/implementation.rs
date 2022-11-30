use lawn_constants::logger::{AsLogStr, Logger};
use lawn_constants::Error;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::marker::Unpin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    Backend, Deserializer, FileType, IsFlush, LinuxOpenMode, LinuxSetattrValidity,
    LinuxStatValidity, LockCommand, LockKind, Metadata, PlainStat, ProtocolTag, ProtocolVersion,
    Serializer, SimpleOpenMode, Stat, Tag, UnixStat,
};

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

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::InvalidSize => write!(f, "invalid size"),
            Self::IOError(e) => write!(f, "i/o error: {}", e),
        }
    }
}

impl std::error::Error for ServerError {}

struct ProtocolData {
    ver: ProtocolVersion,
    max_size: usize,
}

pub struct Server<
    T: Backend + Send + Sync + 'static,
    R: AsyncReadExt + Unpin + Send + Sync,
    W: AsyncWriteExt + Unpin + Send + Sync,
> {
    backend: Arc<T>,
    rd: R,
    wr: W,
    pdata: Arc<RwLock<ProtocolData>>,
    tags: Arc<flurry::HashMap<Tag, Mutex<tokio::sync::mpsc::Receiver<()>>>>,
    logger: Arc<dyn Logger + Send + Sync>,
}

impl<
        T: Backend + Send + Sync + 'static,
        R: AsyncReadExt + Unpin + Send + Sync,
        W: AsyncWriteExt + Unpin + Send + Sync,
    > Server<T, R, W>
{
    /// The largest buffer size we'll allocate.
    ///
    /// This exists to prevent DoS attacks from consuming excessive memory.
    const MAX_BUFFER_SIZE: usize = 1024 * 1024;

    const SIZE_SIZE: usize = 4;
    const MSG_SIZE: usize = 1;
    const TAG_SIZE: usize = 2;
    const HEADER_SIZE: usize = Self::SIZE_SIZE + Self::MSG_SIZE + Self::TAG_SIZE;

    pub fn new(logger: Arc<dyn Logger + Send + Sync>, backend: T, rd: R, wr: W) -> Server<T, R, W> {
        Self {
            logger,
            backend: Arc::new(backend),
            rd,
            wr,
            pdata: Arc::new(RwLock::new(ProtocolData {
                ver: ProtocolVersion::Original,
                max_size: Self::MAX_BUFFER_SIZE + Self::HEADER_SIZE,
            })),
            tags: Arc::new(flurry::HashMap::new()),
        }
    }

    pub fn shutdown(&self) {}

    fn process_message(
        logger: Arc<dyn Logger + Send + Sync>,
        backend: Arc<T>,
        pdata: Arc<RwLock<ProtocolData>>,
        tags: Arc<flurry::HashMap<Tag, Mutex<tokio::sync::mpsc::Receiver<()>>>>,
        msg: ProtocolTag,
        tag: Tag,
        buf: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let meta = Metadata {
            protocol: pdata.read().unwrap().ver,
            tag,
        };
        let d = Deserializer::new(buf);
        let mut s = Serializer::new();
        trace!(
            logger,
            "9P: message {:?} {:?} {}",
            msg,
            meta.protocol,
            hex::encode(&tag.0)
        );
        match (msg, meta.protocol, tag) {
            (ProtocolTag::Tversion, _, _) => {
                let (size, version) = backend.version(&meta, d.read_u32()?, d.read_string()?)?;
                let proto = match std::str::from_utf8(&version).map(ProtocolVersion::from_str) {
                    Ok(Ok(p)) => p,
                    _ => return Err(Error::EOPNOTSUPP),
                };
                {
                    let mut g = pdata.write().unwrap();
                    g.ver = proto;
                    g.max_size = size as usize;
                }
                s.write_u32(size);
                s.write_string(&version)?;
                backend.clunk_all(&meta)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tauth, ProtocolVersion::Original, _) => {
                let qid = backend.auth(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_string()?,
                    None,
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tauth, ProtocolVersion::Unix, _)
            | (ProtocolTag::Tauth, ProtocolVersion::Linux, _) => {
                let qid = backend.auth(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_string()?,
                    Some(d.read_u32()?),
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tattach, ProtocolVersion::Original, _) => {
                let qid = backend.attach(
                    &meta,
                    d.read_fid()?,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_string()?,
                    None,
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tattach, ProtocolVersion::Unix, _)
            | (ProtocolTag::Tattach, ProtocolVersion::Linux, _) => {
                let qid = backend.attach(
                    &meta,
                    d.read_fid()?,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_string()?,
                    Some(d.read_u32()?),
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tclunk, _, _) => {
                backend.clunk(&meta, d.read_fid()?)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tflush, _, _) => {
                match backend.flush(&meta, d.read_tag()?) {
                    // If we get an Ok, the backend has implemented the flush for us and it's
                    // asserted that the flush has completed successsfully.
                    Ok(()) => Ok(s.into_inner()),
                    // If we get an Err, then the backend has said it doesn't implement this
                    // operation and we have to wait for the operation to complete before sending
                    // our reply.
                    Err(_) => {
                        let tg = tags.guard();
                        let rx = tags.remove(&tag, &tg);
                        // If this is Some, then the operation is in progress and we must wait for
                        // it.  If it's None, then the operation has already completed.
                        if let Some(rx) = rx {
                            let mut rx = rx.lock().unwrap();
                            // If this is Ok, then we've successfully waited for the operation to
                            // complete.  If it's Err, then the other end of the channel has been
                            // dropped, and the operation has completed.
                            let _ = rx.blocking_recv();
                        }
                        // By the time we get here, we've waited for the operation to complete.
                        // Now we can send the success message since the operation is no longer in
                        // progress.
                        Ok(s.into_inner())
                    }
                }
            }
            (ProtocolTag::Topen, _, _) => {
                let (fid, mode) = (d.read_fid()?, SimpleOpenMode::from_bits(d.read_u8()?));
                let mode = mode.ok_or(Error::EINVAL)?;
                let (qid, io) = backend.open(&meta, fid, mode)?;
                s.write_qid(qid);
                s.write_u32(io);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tlopen, ProtocolVersion::Linux, _) => {
                let (fid, mode) = (d.read_fid()?, d.read_u32()?);
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {}, mode {:08x}",
                    msg,
                    meta.protocol,
                    fid,
                    mode,
                );
                let mode = LinuxOpenMode::from_bits(mode).ok_or(Error::EINVAL)?;
                let (qid, io) = backend.lopen(&meta, fid, mode)?;
                s.write_qid(qid);
                s.write_u32(io);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tcreate, ProtocolVersion::Original, _) => {
                let (fid, name, perm, mode) = (
                    d.read_fid()?,
                    d.read_string()?,
                    FileType::from_bits(d.read_u32()?),
                    SimpleOpenMode::from_bits(d.read_u8()?),
                );
                let perm = perm.ok_or(Error::EINVAL)?;
                let mode = mode.ok_or(Error::EINVAL)?;
                let (qid, io) = backend.create(&meta, fid, name, perm, mode, None)?;
                s.write_qid(qid);
                s.write_u32(io);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tcreate, ProtocolVersion::Unix, _) => {
                let (fid, name, perm, mode, extension) = (
                    d.read_fid()?,
                    d.read_string()?,
                    FileType::from_bits(d.read_u32()?),
                    SimpleOpenMode::from_bits(d.read_u8()?),
                    d.read_string()?,
                );
                let perm = perm.ok_or(Error::EINVAL)?;
                let mode = mode.ok_or(Error::EINVAL)?;
                let extension = if extension.is_empty() {
                    None
                } else {
                    Some(extension)
                };
                let (qid, io) = backend.create(&meta, fid, name, perm, mode, extension)?;
                s.write_qid(qid);
                s.write_u32(io);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tlcreate, ProtocolVersion::Linux, _) => {
                let (fid, name, flags, mode, gid) = (
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u32()?,
                );
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {} name {} flags {:08x} mode {:08o} gid {}",
                    msg,
                    meta.protocol,
                    fid,
                    name.as_log_str(),
                    flags,
                    mode,
                    gid
                );
                let (qid, io) = backend.lcreate(&meta, fid, name, flags, mode, gid)?;
                s.write_qid(qid);
                s.write_u32(io);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tread, _, _) => {
                let (fid, offset, count) = (d.read_fid()?, d.read_u64()?, d.read_u32()?);
                let mut buf = vec![
                    0u8;
                    std::cmp::min(
                        count as usize,
                        pdata.read().unwrap().max_size - Self::HEADER_SIZE - 4
                    )
                ];
                let count = backend.read(&meta, fid, offset, &mut buf)?;
                let buf = &buf[0..count as usize];
                s.write_u32(count);
                s.write_data(buf);
                Ok(s.into_inner())
            }
            (ProtocolTag::Twrite, _, _) => {
                let (fid, offset, count) = (d.read_fid()?, d.read_u64()?, d.read_u32()?);
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {} offset {} bytes {} total len {}",
                    msg,
                    meta.protocol,
                    fid,
                    offset,
                    count,
                    buf.len(),
                );
                let data = d.read_data(count as usize)?;
                let count = backend.write(&meta, fid, offset, data)?;
                s.write_u32(count);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tremove, _, _) => {
                let fid = d.read_fid()?;
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {}",
                    msg,
                    meta.protocol,
                    fid
                );
                backend.remove(&meta, fid)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tfsync, ProtocolVersion::Linux, _) => {
                backend.fsync(&meta, d.read_fid()?);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tstat, ProtocolVersion::Original, _) => {
                let st = backend.stat(&meta, d.read_fid()?)?;
                let bytes = st.to_bytes().ok_or(Error::EIO)?;
                if bytes.len() >= 2 {
                    trace!(
                        logger,
                        "9P: message {:?} {:?} {} bytes, size {}",
                        msg,
                        meta.protocol,
                        bytes.len(),
                        u16::from_le_bytes(bytes[0..2].try_into().unwrap())
                    );
                }
                s.write_u16(bytes.len() as u16);
                s.write_data(&bytes);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tstat, ProtocolVersion::Unix, _) => {
                let st = backend.stat(&meta, d.read_fid()?)?;
                let bytes = st.to_bytes().ok_or(Error::EIO)?;
                s.write_u16(bytes.len() as u16);
                s.write_data(&bytes);
                Ok(s.into_inner())
            }
            (ProtocolTag::Twstat, ProtocolVersion::Original, _) => {
                let fid = d.read_fid()?;
                let size = d.read_u16()?;
                let st = PlainStat::from_bytes(size, d.read_data(size as usize)?)
                    .ok_or(Error::EINVAL)?;
                if st.is_flush() {
                    backend.fsync(&meta, fid);
                } else {
                    let dst: &dyn Stat = &st;
                    backend.wstat(&meta, fid, dst)?;
                }
                Ok(s.into_inner())
            }
            (ProtocolTag::Twstat, ProtocolVersion::Unix, _) => {
                let fid = d.read_fid()?;
                let size = d.read_u16()?;
                let st =
                    UnixStat::from_bytes(size, d.read_data(size as usize)?).ok_or(Error::EINVAL)?;
                if st.is_flush() {
                    backend.fsync(&meta, fid);
                } else {
                    let dst: &dyn Stat = &st;
                    backend.wstat(&meta, fid, dst)?;
                }
                Ok(s.into_inner())
            }
            (ProtocolTag::Twalk, _, _) => {
                let (fid, newfid, nwname) = (d.read_fid()?, d.read_fid()?, d.read_u16()?);
                let components: Vec<&[u8]> = (0..nwname)
                    .map(|_| d.read_string())
                    .collect::<Result<Vec<&[u8]>, Error>>()?;
                let qids = backend.walk(&meta, fid, newfid, &components)?;
                s.write_u16(qids.len() as u16);
                for qid in qids {
                    s.write_qid(qid);
                }
                Ok(s.into_inner())
            }
            (ProtocolTag::Tsymlink, ProtocolVersion::Linux, _) => {
                let qid = backend.symlink(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_string()?,
                    d.read_u32()?,
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tmknod, ProtocolVersion::Linux, _) => {
                let qid = backend.mknod(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u32()?,
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Trename, ProtocolVersion::Linux, _) => {
                backend.rename(&meta, d.read_fid()?, d.read_fid()?, d.read_string()?)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Treadlink, ProtocolVersion::Linux, _) => {
                let dest = backend.readlink(&meta, d.read_fid()?)?;
                s.write_string(&dest)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tgetattr, ProtocolVersion::Linux, _) => {
                let (fid, validity) = (
                    d.read_fid()?,
                    LinuxStatValidity::from_bits(d.read_u64()?).ok_or(Error::EINVAL)?,
                );
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {} validity {:?}",
                    msg,
                    meta.protocol,
                    fid,
                    validity,
                );
                let st = backend.getattr(&meta, fid, validity)?;
                let (v, validity) = st.to_bytes();
                trace!(
                    logger,
                    "9P: message {:?} {:?} returned validity {:?}",
                    msg,
                    meta.protocol,
                    validity,
                );
                s.write_u64(validity.bits());
                s.write_data(&v);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tsetattr, ProtocolVersion::Linux, _) => {
                let (
                    fid,
                    valid,
                    mode,
                    uid,
                    gid,
                    size,
                    atime_sec,
                    atime_nsec,
                    mtime_sec,
                    mtime_nsec,
                ) = (
                    d.read_fid()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u32()?,
                    d.read_u64()?,
                    d.read_u64()?,
                    d.read_u64()?,
                    d.read_u64()?,
                    d.read_u64()?,
                );
                trace!(
                    logger,
                    "9P: message {:?} {:?} fid {} valid {:08x} mode {:08o} uid {} gid {} size {} atime {}/{} mtime {}/{}",
                    msg,
                    meta.protocol,
                    fid,
                    valid,
                    mode,
                    uid,
                    gid,
                    size,
                    atime_sec,
                    atime_nsec,
                    mtime_sec,
                    mtime_nsec,
                );
                let valid = LinuxSetattrValidity::from_bits(valid).ok_or(Error::EINVAL)?;
                let mode = if valid.contains(LinuxSetattrValidity::MODE) {
                    Some(mode)
                } else {
                    None
                };
                let uid = if valid.contains(LinuxSetattrValidity::UID) {
                    Some(uid)
                } else {
                    None
                };
                let gid = if valid.contains(LinuxSetattrValidity::GID) {
                    Some(gid)
                } else {
                    None
                };
                let size = if valid.contains(LinuxSetattrValidity::SIZE) {
                    Some(size)
                } else {
                    None
                };
                let (atime, set_atime) = if valid
                    .contains(LinuxSetattrValidity::ATIME | LinuxSetattrValidity::ATIME_SET)
                {
                    (
                        Some(
                            SystemTime::UNIX_EPOCH
                                + Duration::from_secs(atime_sec)
                                + Duration::from_nanos(atime_nsec),
                        ),
                        true,
                    )
                } else if valid.contains(LinuxSetattrValidity::ATIME) {
                    (None, true)
                } else {
                    (None, false)
                };
                let (mtime, set_mtime) = if valid
                    .contains(LinuxSetattrValidity::ATIME | LinuxSetattrValidity::ATIME_SET)
                {
                    (
                        Some(
                            SystemTime::UNIX_EPOCH
                                + Duration::from_secs(mtime_sec)
                                + Duration::from_nanos(mtime_nsec),
                        ),
                        true,
                    )
                } else if valid.contains(LinuxSetattrValidity::ATIME) {
                    (None, true)
                } else {
                    (None, false)
                };
                backend.setattr(
                    &meta, fid, mode, uid, gid, size, atime, mtime, set_atime, set_mtime,
                )?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Txattrwalk, ProtocolVersion::Linux, _) => {
                let size =
                    backend.xattrwalk(&meta, d.read_fid()?, d.read_fid()?, d.read_string()?)?;
                s.write_u64(size);
                Ok(s.into_inner())
            }
            (ProtocolTag::Txattrcreate, ProtocolVersion::Linux, _) => {
                backend.xattrcreate(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_u64()?,
                    d.read_u32()?,
                )?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Treaddir, ProtocolVersion::Linux, _) => {
                let results =
                    backend.readdir(&meta, d.read_fid()?, d.read_u64()?, d.read_u32()?)?;
                let len: usize = results.iter().map(|e| e.len()).sum();
                s.write_u32(len as u32);
                for entry in results {
                    s.write_qid(entry.qid);
                    s.write_u64(entry.offset);
                    s.write_u8(entry.kind);
                    s.write_string(&entry.name)?;
                }
                Ok(s.into_inner())
            }
            (ProtocolTag::Tlock, ProtocolVersion::Linux, _) => {
                let status = backend.lock(
                    &meta,
                    d.read_fid()?,
                    LockCommand::from_u8(d.read_u8()?).ok_or(Error::EINVAL)?,
                    d.read_u32()?,
                    d.read_u64()?,
                    d.read_u64()?,
                    d.read_u32()?,
                    d.read_string()?,
                )?;
                s.write_u8(status as u8);
                Ok(s.into_inner())
            }
            (ProtocolTag::Tgetlock, ProtocolVersion::Linux, _) => {
                let lock = backend.getlock(
                    &meta,
                    d.read_fid()?,
                    LockKind::from_u8(d.read_u8()?).ok_or(Error::EINVAL)?,
                    d.read_u64()?,
                    d.read_u64()?,
                    d.read_u32()?,
                    d.read_string()?,
                )?;
                s.write_u8(lock.kind as u8);
                s.write_u64(lock.start);
                s.write_u64(lock.length);
                s.write_u32(lock.proc_id);
                s.write_string(&lock.client_id)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tlink, ProtocolVersion::Linux, _) => {
                backend.link(&meta, d.read_fid()?, d.read_fid()?, d.read_string()?)?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tmkdir, ProtocolVersion::Linux, _) => {
                let qid = backend.mkdir(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_u32()?,
                    d.read_u32()?,
                )?;
                s.write_qid(qid);
                Ok(s.into_inner())
            }
            (ProtocolTag::Trenameat, ProtocolVersion::Linux, _) => {
                backend.renameat(
                    &meta,
                    d.read_fid()?,
                    d.read_string()?,
                    d.read_fid()?,
                    d.read_string()?,
                )?;
                Ok(s.into_inner())
            }
            (ProtocolTag::Tunlinkat, ProtocolVersion::Linux, _) => {
                backend.unlinkat(&meta, d.read_fid()?, d.read_string()?, d.read_u32()?)?;
                Ok(s.into_inner())
            }
            _ => Err(Error::EOPNOTSUPP),
        }
    }

    async fn send_message(&mut self, msg: u8, tag: Tag, body: &[u8]) -> Result<(), ServerError> {
        let len = 7u32 + body.len() as u32;
        let len = len.to_le_bytes();
        let prefix = [len[0], len[1], len[2], len[3], msg, tag.0[0], tag.0[1]];
        self.wr.write_all(&prefix).await?;
        self.wr.write_all(body).await?;
        Ok(())
    }

    async fn send_error(&mut self, tag: Tag, err: Error) -> Result<(), ServerError> {
        let mut s = Serializer::new();
        let (msg, body) = match self.pdata.read().unwrap().ver {
            ProtocolVersion::Original => {
                let _ = s.write_string(format!("{}", err).as_bytes());
                (ProtocolTag::Rerror, s.into_inner())
            }
            ProtocolVersion::Unix => {
                let _ = s.write_string(format!("{}", err).as_bytes());
                s.write_u32(err as u32);
                (ProtocolTag::Rerror, s.into_inner())
            }
            ProtocolVersion::Linux => {
                s.write_u32(err as u32);
                (ProtocolTag::Rlerror, s.into_inner())
            }
        };
        trace!(self.logger, "9P: sending error {:?} {:?} {}", msg, err, err);
        self.send_message(msg as u8, tag, &body).await
    }

    async fn parse_message(&mut self, buf: &[u8; 7]) -> Result<(), ServerError> {
        let size = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let msg = ProtocolTag::from_u8(buf[4]);
        let tag = Tag(buf[5..7].try_into().unwrap());
        if size < 7 || size as usize > self.pdata.read().unwrap().max_size {
            return Err(ServerError::InvalidSize);
        }
        let mut v = vec![0u8; (size as usize) - 7];
        self.rd.read_exact(&mut v).await?;
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        {
            let tags = self.tags.clone();
            let tg = tags.guard();
            self.tags.insert(tag, Mutex::new(rx), &tg);
        }
        let msg = match msg {
            Some(msg) => {
                trace!(
                    self.logger,
                    "9P: message {:?} ({:02x}) size {:08x} tag {:02x}{:02x}",
                    msg,
                    msg as u8,
                    size,
                    tag.0[0],
                    tag.0[1]
                );
                msg
            }
            None => {
                trace!(
                    self.logger,
                    "9P: unknown message {:02x} size {:08x} tag {:02x}{:02x}",
                    buf[4],
                    size,
                    tag.0[0],
                    tag.0[1]
                );
                self.send_error(tag, Error::EOPNOTSUPP).await?;
                return Ok(());
            }
        };
        let logger = self.logger.clone();
        let backend = self.backend.clone();
        let pdata = self.pdata.clone();
        let tags = self.tags.clone();
        let result = match tokio::task::spawn_blocking(move || {
            Self::process_message(logger, backend, pdata, tags, msg, tag, &v)
        })
        .await
        .unwrap()
        {
            Ok(body) => {
                trace!(self.logger, "9P: message {:?} ok, sending response", msg);
                self.send_message(msg as u8 + 1, tag, &body).await?;
                Ok(())
            }
            Err(e) => self.send_error(tag, e).await,
        };
        let _ = tx.send(()).await;
        {
            let tg = self.tags.guard();
            self.tags.remove(&tag, &tg);
        }
        result
    }

    pub async fn run(&mut self) -> Result<(), ServerError> {
        trace!(self.logger, "9P: starting server");
        loop {
            let mut buf = [0u8; 7];
            let res = self.rd.read(&mut buf).await;
            trace!(self.logger, "9P: read data");
            match res {
                Ok(7) => {
                    trace!(self.logger, "9P: message header received");
                    self.parse_message(&buf).await?;
                }
                Ok(0) => return Ok(()),
                Ok(n) => {
                    trace!(self.logger, "9P: partial message header received");
                    self.rd.read_exact(&mut buf[n..7]).await?;
                    self.parse_message(&buf).await?;
                }
                Err(e) => {
                    trace!(self.logger, "9P: got error {} on read", e);
                    return Err(ServerError::IOError(e));
                }
            }
        }
    }
}
