use super::{Backend, FileKind, QIDMapper, Result, ToIdentifier};
use crate::server::{
    DirEntry, FileType, IsFlush, LinuxFileType, LinuxOpenMode, LinuxStat, LinuxStatValidity, Lock,
    LockCommand, LockKind, LockStatus, Metadata, PlainStat, ProtocolVersion, SimpleOpenMode, Stat,
    Tag, UnixStat, FID, QID,
};
use lawn_constants::logger::{AsLogStr, Logger};
use lawn_constants::Error;
use lawn_fs::backend as fsbackend;
use std::cmp;
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Clone)]
struct OpenFileID {
    dev: u64,
    ino: u64,
    file: Arc<File>,
    full_path: PathBuf,
}

impl ToIdentifier for OpenFileID {
    fn to_identifier(&self) -> Vec<u8> {
        let mut buf = [0u8; 8 + 8];
        buf[0..8].copy_from_slice(&self.dev.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ino.to_le_bytes());
        buf.into()
    }
}

impl Eq for OpenFileID {}

impl PartialEq for OpenFileID {
    fn eq(&self, other: &OpenFileID) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl PartialOrd for OpenFileID {
    fn partial_cmp(&self, other: &OpenFileID) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OpenFileID {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.dev
            .cmp(&other.dev)
            .then_with(|| self.ino.cmp(&other.ino))
            .then_with(|| self.file.as_raw_fd().cmp(&other.file.as_raw_fd()))
            .then_with(|| self.full_path.cmp(&other.full_path))
    }
}

impl IDInfo for OpenFileID {
    fn dev(&self) -> u64 {
        self.dev
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn file(&self) -> Option<Arc<File>> {
        Some(self.file.clone())
    }

    fn full_path(&self) -> &Path {
        &self.full_path
    }

    fn full_path_bytes(&self) -> &[u8] {
        self.full_path.as_os_str().as_bytes()
    }

    fn file_kind(&self) -> Result<FileKind> {
        Ok(FileKind::from_metadata(&self.file.metadata()?))
    }
}

struct FileID {
    dev: u64,
    ino: u64,
    full_path: PathBuf,
}

impl ToIdentifier for FileID {
    fn to_identifier(&self) -> Vec<u8> {
        let mut buf = [0u8; 8 + 8];
        buf[0..8].copy_from_slice(&self.dev.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ino.to_le_bytes());
        buf.into()
    }
}

impl Eq for FileID {}

impl PartialEq for FileID {
    fn eq(&self, other: &FileID) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl PartialOrd for FileID {
    fn partial_cmp(&self, other: &FileID) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileID {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.dev
            .cmp(&other.dev)
            .then_with(|| self.ino.cmp(&other.ino))
            .then_with(|| self.full_path.cmp(&other.full_path))
    }
}

impl IDInfo for FileID {
    fn dev(&self) -> u64 {
        self.dev
    }

    fn ino(&self) -> u64 {
        self.ino
    }

    fn file(&self) -> Option<Arc<File>> {
        None
    }

    fn full_path(&self) -> &Path {
        &self.full_path
    }

    fn full_path_bytes(&self) -> &[u8] {
        self.full_path.as_os_str().as_bytes()
    }

    fn file_kind(&self) -> Result<FileKind> {
        Ok(FileKind::from_metadata(&fs::symlink_metadata(
            &self.full_path,
        )?))
    }
}

trait IDInfo {
    fn dev(&self) -> u64;
    fn ino(&self) -> u64;
    fn file(&self) -> Option<Arc<File>>;
    fn full_path(&self) -> &Path;
    fn full_path_bytes(&self) -> &[u8];
    fn file_kind(&self) -> Result<FileKind>;
}

// These constants are arbitrary but are designed to not share byte patterns to help in debugging.
// These fields are not otherwise used and so any dummy value is fine.
const MAGIC_KIND: u16 = 0xfeff;
const MAGIC_DEV: u32 = 0xc0c1c2c3;

#[allow(clippy::unnecessary_cast)]
#[cfg(target_os = "linux")]
fn major_minor(dev: u64) -> (u32, u32) {
    (
        rustix::fs::major(dev as rustix::fs::Dev) as u32,
        rustix::fs::minor(dev as rustix::fs::Dev) as u32,
    )
}

#[cfg(target_os = "macos")]
fn major_minor(dev: u64) -> (u32, u32) {
    let major = dev >> 24;
    let minor = dev & 0x00ffffff;
    (major as u32, minor as u32)
}

#[cfg(target_os = "freebsd")]
fn major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev >> 32) & 0xffffff00) | ((dev >> 8) & 0xff);
    let minor = ((dev >> 24) & 0xff00) | (dev & 0xffff00ff);
    (major as u32, minor as u32)
}

#[cfg(target_os = "netbsd")]
fn major_minor(dev: u64) -> (u32, u32) {
    let major = (dev & 0x000fff00) >> 8;
    let minor = ((dev & 0xfff00000) >> 12) | (dev & 0xff);
    (major as u32, minor as u32)
}

trait FromMetadata: Sized {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self>;
}

impl FromMetadata for PlainStat {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        let len = Self::FIXED_SIZE - 2;
        Some(Self {
            size: len.try_into().ok()?,
            kind: MAGIC_KIND,
            dev: MAGIC_DEV,
            qid: QID([0u8; 13]),
            mode: FileType::from_metadata(meta).bits(),
            atime: meta.atime().try_into().unwrap_or(0),
            mtime: meta.mtime().try_into().unwrap_or(0),
            length: meta.len(),
            name: Vec::new(),
            uid: Vec::new(),
            gid: Vec::new(),
            muid: Vec::new(),
        })
    }
}

impl FromMetadata for UnixStat {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        let ft = meta.file_type();
        let extension = if ft.is_block_device() {
            let (maj, min) = major_minor(meta.rdev());
            format!("b {} {}", maj, min).into_bytes()
        } else if ft.is_char_device() {
            let (maj, min) = major_minor(meta.rdev());
            format!("c {} {}", maj, min).into_bytes()
        } else {
            Vec::new()
        };
        let len = Self::FIXED_SIZE + extension.len() - 2;
        Some(Self {
            size: len.try_into().ok()?,
            kind: MAGIC_KIND,
            dev: MAGIC_DEV,
            qid: QID([0u8; 13]),
            mode: FileType::from_metadata(meta).bits(),
            atime: meta.atime().try_into().unwrap_or(0),
            mtime: meta.mtime().try_into().unwrap_or(0),
            length: meta.len(),
            name: Vec::new(),
            uid: Vec::new(),
            gid: Vec::new(),
            muid: Vec::new(),
            extension,
            nuid: meta.uid(),
            ngid: meta.gid(),
            nmuid: u32::MAX,
        })
    }
}

impl FromMetadata for LinuxStat {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        let mode = LinuxFileType::from_unix(meta.mode());
        Some(Self {
            qid: QID([0u8; 13]),
            mode: mode.bits(),
            uid: meta.uid(),
            gid: meta.gid(),
            nlink: Some(meta.nlink()),
            rdev: Some(meta.rdev()),
            length: meta.len(),
            blksize: meta.blksize(),
            blocks: Some(meta.blocks()),
            atime_sec: meta.atime().try_into().ok(),
            atime_nsec: meta.atime_nsec().try_into().ok(),
            mtime_sec: meta.mtime().try_into().ok(),
            mtime_nsec: meta.mtime_nsec().try_into().ok(),
            ctime_sec: meta.ctime().try_into().ok(),
            ctime_nsec: meta.ctime_nsec().try_into().ok(),
            btime_sec: None,
            btime_nsec: None,
            gen: None,
            data_version: None,
        })
    }
}

#[allow(clippy::type_complexity)]
pub struct LibcBackend {
    max_size: u32,
    backend: Arc<dyn fsbackend::Backend + Send + Sync>,
    qidmapper: QIDMapper,
    logger: Arc<dyn Logger + Send + Sync>,
}

impl LibcBackend {
    pub fn new(
        logger: Arc<dyn Logger + Send + Sync>,
        backend: Arc<dyn fsbackend::Backend + Send + Sync>,
        max_size: u32,
    ) -> LibcBackend {
        Self {
            max_size,
            backend,
            qidmapper: QIDMapper::new(),
            logger,
        }
    }

    fn temp_backend_fid(&self, fid: FID, offset: u32) -> fsbackend::FID {
        fsbackend::FID::new(((offset as u64) << 32) | u32::from_le_bytes(fid.0) as u64)
    }

    #[allow(clippy::unnecessary_cast)]
    #[allow(unused_unsafe)]
    fn parse_major_minor(&self, s: &[u8]) -> Result<(fsbackend::FileType, u32, u32)> {
        let mut items = s.split(|b| *b == b' ');
        let mmode = match items.next() {
            Some(b"b") => fsbackend::FileType::S_IFBLK,
            Some(b"c") => fsbackend::FileType::S_IFCHR,
            _ => return Err(Error::EINVAL),
        };
        let smaj = items.next();
        let smin = items.next();
        let (smaj, smin) = match (smaj, smin) {
            (Some(smaj), Some(smin)) => (smaj, smin),
            _ => return Err(Error::EINVAL),
        };
        let (smaj, smin) = match (std::str::from_utf8(smaj), std::str::from_utf8(smin)) {
            (Ok(maj), Ok(min)) => (maj, min),
            _ => return Err(Error::EINVAL),
        };
        let (maj, min) = match (smaj.parse(), smin.parse()) {
            (Ok(maj), Ok(min)) => (maj, min),
            _ => return Err(Error::EINVAL),
        };
        Ok((mmode, maj, min))
    }
}

impl Backend for LibcBackend {
    fn version(&self, _meta: &Metadata, max_size: u32, version: &[u8]) -> Result<(u32, Vec<u8>)> {
        let max_size = std::cmp::min(max_size, self.max_size);
        let proto = match std::str::from_utf8(version).map(ProtocolVersion::from_str) {
            Ok(Ok(ProtocolVersion::Original)) => ProtocolVersion::Original,
            Ok(Ok(ProtocolVersion::Unix)) => ProtocolVersion::Unix,
            Ok(Ok(ProtocolVersion::Linux)) => ProtocolVersion::Linux,
            _ => return Err(Error::EOPNOTSUPP),
        };
        Ok((max_size, proto.to_str().as_bytes().into()))
    }

    fn auth(
        &self,
        meta: &Metadata,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let meta = meta.into();
        self.backend
            .auth(&meta, afid.into(), uname, aname, nuname)
            .map(|qid| self.qidmapper.qid(qid))
    }

    fn attach(
        &self,
        meta: &Metadata,
        fid: FID,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let meta = meta.into();
        let afid = match afid {
            FID([0xff, 0xff, 0xff, 0xff]) => None,
            f => Some(f.into()),
        };
        self.backend
            .attach(&meta, fid.into(), afid, uname, aname, nuname)
            .map(|qid| self.qidmapper.qid(qid))
    }

    fn clunk(&self, meta: &Metadata, fid: FID) -> Result<()> {
        let meta = meta.into();
        self.backend.clunk(&meta, fid.into())
    }

    fn clunk_all(&self, meta: &Metadata) -> Result<()> {
        let meta = meta.into();
        self.backend.clunk_all(&meta)
    }

    fn flush(&self, meta: &Metadata, tag: Tag) -> Result<()> {
        let meta = meta.into();
        self.backend.flush(&meta, tag.into())
    }

    fn open(&self, meta: &Metadata, fid: FID, mode: SimpleOpenMode) -> Result<(QID, u32)> {
        let meta = meta.into();
        let (qid, iounit) = self.backend.open(&meta, fid.into(), mode.into())?;
        Ok((self.qidmapper.qid(qid), iounit.unwrap_or(0)))
    }

    fn lopen(&self, meta: &Metadata, fid: FID, mode: LinuxOpenMode) -> Result<(QID, u32)> {
        let meta = meta.into();
        let (qid, iounit) = self.backend.open(&meta, fid.into(), mode)?;
        Ok((self.qidmapper.qid(qid), iounit.unwrap_or(0)))
    }
    #[allow(clippy::unnecessary_cast)]
    fn create(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        perm: FileType,
        omode: SimpleOpenMode,
        extension: Option<&[u8]>,
    ) -> Result<(QID, u32)> {
        let meta = meta.into();
        trace!(
            self.logger,
            "9P create: fid {} name {} perm {:?} omode {:?}",
            fid,
            name.as_log_str(),
            perm,
            omode
        );
        let mut mode = perm.bits() & 0o777;
        if perm.contains(FileType::DMSETUID) {
            mode |= 0o4000;
        }
        if perm.contains(FileType::DMSETGID) {
            mode |= 0o2000;
        }
        if perm
            .contains(FileType::DMAPPEND | FileType::DMMOUNT | FileType::DMAUTH | FileType::DMTMP)
        {
            return Err(Error::EINVAL);
        }
        trace!(self.logger, "9P create: unix mode {:04o}", mode);
        let (mmode, mmajor, mminor) = match (
            perm & !(FileType::DMACCMODE | FileType::DMSETUID | FileType::DMSETGID),
            extension,
        ) {
            (FileType::DMDIR, None) => {
                trace!(self.logger, "9P create: directory: {}", name.as_log_str());
                let mode = fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)?;
                let qid = self.backend.mkdir(&meta, fid.into(), name, mode, None)?;
                trace!(
                    self.logger,
                    "9P create: directory creation OK, updating fid"
                );
                self.backend
                    .resolve(&meta, fid.into(), fid.into(), &[name])?;
                return Ok((self.qidmapper.qid(qid), 0));
            }
            (FileType::DMSYMLINK, Some(dest)) => {
                trace!(
                    self.logger,
                    "9P create: symlink: {} {}",
                    name.as_log_str(),
                    dest.as_log_str()
                );
                let qid = self.backend.symlink(&meta, fid.into(), name, dest, None)?;
                self.backend
                    .resolve(&meta, fid.into(), fid.into(), &[name])?;
                return Ok((self.qidmapper.qid(qid), 0));
            }
            (x, None) if x == FileType::empty() => {
                trace!(self.logger, "9P create: file: {}", name.as_log_str());
                let mode = fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)?;
                let qid = self.backend.create(
                    &meta,
                    fid.into(),
                    fid.into(),
                    name,
                    omode.into(),
                    mode,
                    None,
                )?;
                return Ok((self.qidmapper.qid(qid.0), 0));
            }
            (FileType::DMDEVICE, Some(kind)) => self.parse_major_minor(kind)?,
            (FileType::DMSOCKET, None) => (fsbackend::FileType::S_IFSOCK, 0, 0),
            (FileType::DMNAMEDPIPE, None) => (fsbackend::FileType::S_IFIFO, 0, 0),
            _ => return Err(Error::EINVAL),
        };
        let mode = fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)? | mmode;
        trace!(self.logger, "9P create: mknod: {}", name.as_log_str());
        let qid = self
            .backend
            .mknod(&meta, fid.into(), name, mode, mmajor, mminor, None)?;
        self.backend
            .resolve(&meta, fid.into(), fid.into(), &[name])?;
        Ok((self.qidmapper.qid(qid), 0))
    }

    fn lcreate(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        flags: u32,
        mode: u32,
        _gid: u32,
    ) -> Result<(QID, u32)> {
        let meta = meta.into();
        let mode = fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)?;
        let flags = fsbackend::OpenMode::from_bits(flags).ok_or(Error::EINVAL)?
            | fsbackend::OpenMode::O_CREAT;
        let qid = self
            .backend
            .create(&meta, fid.into(), fid.into(), name, flags, mode, None)?;
        Ok((self.qidmapper.qid(qid.0), 0))
    }

    fn read(&self, meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32> {
        let bmeta = meta.into();
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        let st = self
            .backend
            .getattr(&bmeta, fid.into(), fsbackend::StatValidity::BASIC)?;
        let is_open = self.backend.is_open(&bmeta, fid.into())?;
        let mode = fsbackend::FileType::from_bits(st.mode).ok_or(Error::EIO)?;
        match (mode & fsbackend::FileType::S_IFMT, is_open) {
            (fsbackend::FileType::S_IFDIR, true) => {
                type BoxDirEntryFn = Box<dyn FnMut(&fsbackend::DirEntry) -> usize>;
                let (offsetf, lenf): (BoxDirEntryFn, BoxDirEntryFn) = match meta.protocol {
                    ProtocolVersion::Original => (
                        Box::new(|de| PlainStat::FIXED_SIZE + de.name.len()),
                        Box::new(|de| PlainStat::FIXED_SIZE + de.name.len()),
                    ),
                    ProtocolVersion::Unix | ProtocolVersion::Linux => (
                        Box::new(|de| {
                            UnixStat::FIXED_SIZE
                                + de.name.len()
                                + de.extension.as_ref().map(|e| e.len()).unwrap_or_default()
                        }),
                        Box::new(|de| {
                            UnixStat::FIXED_SIZE
                                + de.name.len()
                                + de.extension.as_ref().map(|e| e.len()).unwrap_or_default()
                        }),
                    ),
                };
                let entries = self.backend.readdir(
                    &bmeta,
                    fid.into(),
                    offset,
                    data.len() as u32,
                    offsetf,
                    lenf,
                )?;
                let mut size = 0;
                for entry in entries {
                    let fsmeta = &entry.metadata;
                    match meta.protocol {
                        ProtocolVersion::Original => {
                            let mut st = PlainStat::from_metadata(fsmeta).ok_or(Error::EIO)?;
                            st.qid = self.qidmapper.qid(entry.qid);
                            st.size += entry.name.len() as u16;
                            st.name = entry.name;
                            let st = st.to_bytes().ok_or(Error::EIO)?;
                            data[size..size + st.len()].copy_from_slice(&st);
                            size += st.len();
                        }
                        ProtocolVersion::Unix | ProtocolVersion::Linux => {
                            let mut st = UnixStat::from_metadata(fsmeta).ok_or(Error::EIO)?;
                            st.qid = self.qidmapper.qid(entry.qid);
                            st.size += entry.name.len() as u16;
                            st.name = entry.name;
                            st.extension = entry.extension.unwrap_or_default();
                            let st = st.to_bytes().ok_or(Error::EIO)?;
                            data[size..size + st.len()].copy_from_slice(&st);
                            size += st.len();
                        }
                    }
                }
                Ok(size as u32)
            }
            (_, true) => match self.backend.read(&bmeta, fid.into(), offset, data) {
                Ok(len) => Ok(len),
                Err(e) => Err(e),
            },
            (_, false) => Err(Error::EBADF),
        }
    }

    fn write(&self, meta: &Metadata, fid: FID, offset: u64, data: &[u8]) -> Result<u32> {
        let meta = meta.into();
        trace!(
            self.logger,
            "9P write: fid {} offset {} bytes {}",
            fid,
            offset,
            data.len()
        );
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        trace!(self.logger, "9P write: validated data");
        self.backend.write(&meta, fid.into(), offset, data)
    }

    fn remove(&self, meta: &Metadata, fid: FID) -> Result<()> {
        let meta = meta.into();
        trace!(self.logger, "9P remove: fid {}", fid);
        let r = self.backend.remove(&meta, fid.into());
        let _ = self.backend.clunk(&meta, fid.into());
        r
    }

    fn fsync(&self, meta: &Metadata, fid: FID) {
        let meta = meta.into();
        self.backend.fsync(&meta, fid.into());
    }

    fn stat(&self, meta: &Metadata, fid: FID) -> Result<Box<dyn Stat>> {
        trace!(self.logger, "9P stat: fid {}", fid);
        let bmeta = meta.into();
        let st = self
            .backend
            .getattr(&bmeta, fid.into(), fsbackend::StatValidity::BASIC)?;
        match meta.protocol {
            ProtocolVersion::Original => {
                trace!(self.logger, "9P stat: found fid {}", fid);
                if st.qid.kind() == fsbackend::QIDKind::Authentication {
                    let qid = self.qidmapper.qid(st.qid);
                    return Ok(Box::new(PlainStat {
                        size: UnixStat::FIXED_SIZE as u16,
                        kind: 0,
                        dev: 0,
                        qid,
                        mode: FileType::DMAUTH.bits(),
                        atime: 0,
                        mtime: 0,
                        length: 0,
                        name: Vec::new(),
                        uid: Vec::new(),
                        gid: Vec::new(),
                        muid: Vec::new(),
                    }));
                }
                let name = self
                    .backend
                    .pathname(&bmeta, fid.into())?
                    .pop()
                    .ok_or(Error::EIO)?;
                let pst = PlainStat {
                    size: (PlainStat::FIXED_SIZE - 2 + name.len()) as u16,
                    kind: MAGIC_KIND,
                    dev: MAGIC_DEV,
                    qid: self.qidmapper.qid(st.qid),
                    mode: FileType::from_unix(st.mode).bits(),
                    atime: st.atime_sec.and_then(|t| t.try_into().ok()).unwrap_or(0),
                    mtime: st.mtime_sec.and_then(|t| t.try_into().ok()).unwrap_or(0),
                    length: st.length,
                    name,
                    uid: Vec::new(),
                    gid: Vec::new(),
                    muid: Vec::new(),
                };
                trace!(
                    self.logger,
                    "9P stat: created plain stat of {} bytes",
                    pst.size + 2
                );
                Ok(Box::new(pst))
            }
            ProtocolVersion::Unix => {
                trace!(self.logger, "9P stat: found fid {}", fid);
                if st.qid.kind() == fsbackend::QIDKind::Authentication {
                    let qid = self.qidmapper.qid(st.qid);
                    return Ok(Box::new(UnixStat {
                        size: UnixStat::FIXED_SIZE as u16,
                        kind: 0,
                        dev: 0,
                        qid,
                        mode: FileType::DMAUTH.bits(),
                        atime: 0,
                        mtime: 0,
                        length: 0,
                        name: Vec::new(),
                        uid: Vec::new(),
                        gid: Vec::new(),
                        muid: Vec::new(),
                        extension: Vec::new(),
                        nuid: u32::MAX,
                        ngid: u32::MAX,
                        nmuid: u32::MAX,
                    }));
                }
                let name = self
                    .backend
                    .pathname(&bmeta, fid.into())?
                    .pop()
                    .ok_or(Error::EIO)?;
                let extension = if st.qid.kind() == fsbackend::QIDKind::Symlink {
                    self.backend.readlink(&bmeta, fid.into())?
                } else {
                    Vec::new()
                };
                let ust = UnixStat {
                    size: (UnixStat::FIXED_SIZE - 2 + name.len() + extension.len()) as u16,
                    kind: MAGIC_KIND,
                    dev: MAGIC_DEV,
                    qid: self.qidmapper.qid(st.qid),
                    mode: FileType::from_unix(st.mode).bits(),
                    atime: st.atime_sec.and_then(|t| t.try_into().ok()).unwrap_or(0),
                    mtime: st.mtime_sec.and_then(|t| t.try_into().ok()).unwrap_or(0),
                    length: st.length,
                    name,
                    uid: Vec::new(),
                    gid: Vec::new(),
                    muid: Vec::new(),
                    nuid: u32::MAX,
                    ngid: u32::MAX,
                    nmuid: u32::MAX,
                    extension,
                };
                trace!(
                    self.logger,
                    "9P stat: created unix stat of {} bytes",
                    ust.size + 2
                );
                Ok(Box::new(ust))
            }
            _ => Err(Error::EOPNOTSUPP),
        }
    }

    fn wstat(&self, meta: &Metadata, fid: FID, stat: &dyn Stat) -> Result<()> {
        let bmeta = meta.into();
        match meta.protocol {
            ProtocolVersion::Original | ProtocolVersion::Unix => {
                let is_symlink = stat.qid().0[0] == FileKind::Symlink as u8;
                if !stat.kind().is_flush()
                    || !stat.dev().unwrap_or(u32::MAX).is_flush()
                    || (!is_symlink && stat.extension().is_some())
                {
                    return Err(Error::EINVAL);
                }
                if !stat.name().is_empty() {
                    let tempfid = self.temp_backend_fid(fid, 1);
                    if let Err(e) =
                        self.backend
                            .walk(&bmeta, fid.into(), tempfid, &[b".." as &[u8]])
                    {
                        let _ = self.backend.clunk(&bmeta, tempfid);
                        return Err(e);
                    }
                    let r = self
                        .backend
                        .rename(&bmeta, fid.into(), tempfid, stat.name());
                    let _ = self.backend.clunk(&bmeta, tempfid);
                    r?;
                }
                if is_symlink && stat.extension().is_some() {
                    // We don't yet support changing the destination of a symlink.
                    return Err(Error::EOPNOTSUPP);
                }
                let gid = match stat.ngid() {
                    Some(stgid) if !stgid.is_flush() => Some(stgid),
                    _ => None,
                };
                let mode = stat.mode().map(|stmode| {
                    let mut mode = stmode.bits() & 0o777;
                    if stmode.contains(FileType::DMSETUID) {
                        mode |= 0o4000;
                    }
                    if stmode.contains(FileType::DMSETGID) {
                        mode |= 0o2000;
                    }
                    mode
                });
                let size = if stat.length().is_flush() {
                    None
                } else {
                    Some(stat.length())
                };
                self.backend.setattr(
                    &bmeta,
                    fid.into(),
                    mode,
                    None,
                    gid,
                    size,
                    None,
                    None,
                    false,
                    false,
                )
            }
            _ => Err(Error::EOPNOTSUPP),
        }
    }

    fn walk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<Vec<QID>> {
        trace!(
            self.logger,
            "9P walk: fid {} newfid {} components {}",
            fid,
            newfid,
            name.len()
        );
        let meta = meta.into();
        self.backend
            .walk(&meta, fid.into(), newfid.into(), name)
            .map(|qids| qids.iter().map(|q| self.qidmapper.qid(*q)).collect())
    }

    fn symlink(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        target: &[u8],
        gid: u32,
    ) -> Result<QID> {
        let meta = meta.into();
        self.backend
            .symlink(&meta, fid.into(), name, target, Some(gid))
            .map(|q| self.qidmapper.qid(q))
    }

    fn mknod(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        mode: u32,
        major: u32,
        minor: u32,
        gid: u32,
    ) -> Result<QID> {
        let meta = meta.into();
        let ft = fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)?;
        self.backend
            .mknod(&meta, fid.into(), name, ft, major, minor, Some(gid))
            .map(|q| self.qidmapper.qid(q))
    }

    fn rename(&self, meta: &Metadata, fid: FID, dfid: FID, newname: &[u8]) -> Result<()> {
        let meta = meta.into();
        self.backend.rename(&meta, fid.into(), dfid.into(), newname)
    }

    fn readlink(&self, meta: &Metadata, fid: FID) -> Result<Vec<u8>> {
        let meta = meta.into();
        self.backend.readlink(&meta, fid.into())
    }

    fn getattr(&self, meta: &Metadata, fid: FID, mask: LinuxStatValidity) -> Result<LinuxStat> {
        trace!(self.logger, "9P getattr: fid {} mask {:?}", fid, mask);
        let meta = meta.into();
        let st = self.backend.getattr(
            &meta,
            fid.into(),
            fsbackend::StatValidity::from_bits(mask.bits()).ok_or(Error::EINVAL)?,
        )?;
        Ok(LinuxStat::from_fs(&st, self.qidmapper.qid(st.qid)))
    }

    fn setattr(
        &self,
        meta: &Metadata,
        fid: FID,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<SystemTime>,
        mtime: Option<SystemTime>,
        set_atime: bool,
        set_mtime: bool,
    ) -> Result<()> {
        trace!(
            self.logger,
            "9P setattr: fid {} mode {:?} uid {:?} gid {:?} size {:?} atime {:?}/{} mtime {:?}/{}",
            fid,
            mode,
            uid,
            gid,
            size,
            atime,
            set_atime,
            mtime,
            set_mtime
        );
        let meta = meta.into();
        self.backend.setattr(
            &meta,
            fid.into(),
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            set_atime,
            set_mtime,
        )
    }

    fn xattrwalk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[u8]) -> Result<u64> {
        let meta = meta.into();
        self.backend
            .xattrwalk(&meta, fid.into(), newfid.into(), name)
    }

    fn xattrcreate(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        size: u64,
        flags: u32,
    ) -> Result<()> {
        let meta = meta.into();
        self.backend
            .xattrcreate(&meta, fid.into(), name, size, flags)
    }

    fn readdir(&self, meta: &Metadata, fid: FID, offset: u64, count: u32) -> Result<Vec<DirEntry>> {
        let meta = meta.into();
        self.backend
            .readdir(
                &meta,
                fid.into(),
                offset,
                count,
                Box::new(|_| 1),
                Box::new(|de| 13 + 8 + 1 + 2 + de.name.len()),
            )
            .map(|v| {
                v.iter()
                    .map(|de| DirEntry::from_fs(de, self.qidmapper.qid(de.qid)))
                    .collect()
            })
    }

    fn lock(
        &self,
        meta: &Metadata,
        fid: FID,
        kind: LockCommand,
        flags: u32,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: &[u8],
    ) -> Result<LockStatus> {
        let meta = meta.into();
        self.backend
            .lock(
                &meta,
                fid.into(),
                kind.into(),
                flags,
                start,
                length,
                proc_id,
                client_id,
            )
            .map(|status| status.into())
    }

    fn getlock(
        &self,
        meta: &Metadata,
        fid: FID,
        kind: LockKind,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: &[u8],
    ) -> Result<Lock> {
        let meta = meta.into();
        self.backend
            .getlock(
                &meta,
                fid.into(),
                kind.into(),
                start,
                length,
                proc_id,
                client_id,
            )
            .map(|lock| lock.into())
    }

    fn link(&self, meta: &Metadata, dfid: FID, fid: FID, name: &[u8]) -> Result<()> {
        let meta = meta.into();
        self.backend.link(&meta, dfid.into(), fid.into(), name)
    }

    fn mkdir(&self, meta: &Metadata, dfid: FID, name: &[u8], mode: u32, gid: u32) -> Result<QID> {
        let meta = meta.into();
        self.backend
            .mkdir(
                &meta,
                dfid.into(),
                name,
                fsbackend::FileType::from_bits(mode).ok_or(Error::EINVAL)?,
                Some(gid),
            )
            .map(|q| self.qidmapper.qid(q))
    }

    fn renameat(
        &self,
        meta: &Metadata,
        olddirfid: FID,
        oldname: &[u8],
        newdirfid: FID,
        newname: &[u8],
    ) -> Result<()> {
        trace!(
            self.logger,
            "9P renameat: {}/{} -> {}/{}",
            olddirfid,
            oldname.as_log_str(),
            newdirfid,
            newname.as_log_str()
        );
        let meta = meta.into();
        self.backend
            .renameat(&meta, olddirfid.into(), oldname, newdirfid.into(), newname)
    }

    fn unlinkat(&self, meta: &Metadata, dirfd: FID, name: &[u8], flags: u32) -> Result<()> {
        let meta = meta.into();
        self.backend.unlinkat(&meta, dirfd.into(), name, flags)
    }
}

#[cfg(not(miri))]
#[cfg(test)]
mod tests {
    use super::LibcBackend;
    use crate::backend::{Backend, ToIdentifier};
    use crate::server::{
        FileType, LinuxFileType, LinuxOpenMode, LinuxStatValidity, Metadata, PlainStat,
        ProtocolVersion, SimpleOpenMode, Tag, UnixStat, FID,
    };
    use lawn_constants::logger::{LogFormat, LogLevel};
    use lawn_constants::Error;
    use lawn_fs::auth::{AuthenticationInfo, Authenticator, AuthenticatorHandle};
    use lawn_fs::backend as fsbackend;
    use std::collections::HashSet;
    use std::convert::TryInto;
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::FileType as StdFileType;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub struct AutherHandle {
        user: Vec<u8>,
        dir: Vec<u8>,
        id: Option<u32>,
    }

    impl AuthenticatorHandle for AutherHandle {
        fn read(&self, _data: &mut [u8]) -> Result<u32, Error> {
            Err(Error::EOPNOTSUPP)
        }

        fn write(&self, _data: &[u8]) -> Result<u32, Error> {
            Err(Error::EOPNOTSUPP)
        }

        fn info<'a>(&'a self) -> Option<AuthenticationInfo<'a>> {
            Some(AuthenticationInfo::new(
                self.id,
                &*self.user,
                &*self.dir,
                &*self.dir,
            ))
        }
    }

    impl ToIdentifier for AutherHandle {
        fn to_identifier(&self) -> Vec<u8> {
            let mut v = Vec::with_capacity(8 + self.user.len() + 8 + self.dir.len() + 4);
            v.extend(&(self.user.len() as u64).to_le_bytes());
            v.extend(&self.user);
            v.extend(&(self.dir.len() as u64).to_le_bytes());
            v.extend(&self.dir);
            if let Some(id) = self.id {
                v.extend(&id.to_le_bytes());
            }
            v
        }
    }

    pub struct Auther {
        user: Vec<u8>,
        dir: Vec<u8>,
    }

    impl Authenticator for Auther {
        fn create(
            &self,
            _meta: &fsbackend::Metadata,
            _uname: &[u8],
            _aname: &[u8],
            nuname: Option<u32>,
        ) -> Box<dyn AuthenticatorHandle + Send + Sync> {
            Box::new(AutherHandle {
                user: self.user.clone(),
                dir: self.dir.clone(),
                id: nuname,
            })
        }
    }

    struct Logger {}

    impl lawn_constants::logger::Logger for Logger {
        fn level(&self) -> LogLevel {
            LogLevel::Trace
        }
        fn format(&self) -> LogFormat {
            LogFormat::Text
        }
        fn fatal(&self, _msg: &str) {}
        fn error(&self, _msg: &str) {}
        fn message(&self, _msg: &str) {}
        fn info(&self, _msg: &str) {}
        fn debug(&self, _msg: &str) {}
        fn trace(&self, msg: &str) {
            eprintln!("{}", msg);
        }
    }

    type Server = LibcBackend;

    #[allow(dead_code)]
    struct TestInstance {
        dir: TempDir,
        root: PathBuf,
        version: ProtocolVersion,
        server: Server,
        tag: Mutex<u16>,
    }

    impl TestInstance {
        fn next_meta(&self) -> Metadata {
            let mut g = self.tag.lock().unwrap();
            let tag = *g;
            *g += 1;
            Metadata {
                protocol: self.version,
                tag: Tag(tag.to_le_bytes()),
            }
        }
    }

    fn instance(version: ProtocolVersion) -> TestInstance {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let logger = Arc::new(Logger {});
        let backend = Arc::new(lawn_fs::backend::libc::LibcBackend::new(
            logger.clone(),
            Arc::new(Auther {
                user: "foo".into(),
                dir: dir.path().as_os_str().as_bytes().into(),
            }),
            1024 * 1024,
        ));
        TestInstance {
            version,
            server: Server::new(logger.clone(), backend, 1024 * 1024),
            dir,
            root,
            tag: Mutex::new(0),
        }
    }

    /// A permutation on the 32-bit integers.
    ///
    /// This is the Alzette ARX-box reduced from 64 bits to 32 bits, with the constant fixed ad
    /// 0xb7e1, and the shift counts ANDed with 0xf.  The exact algorithm doesn't matter very much,
    /// but this one provides a good distribution.
    fn minialzette(n: u32) -> u32 {
        const C: u16 = 0xb7e1;
        let (mut x, mut y) = ((n >> 16) as u16, n as u16);
        x = x.wrapping_add(y.rotate_right(15));
        y ^= x.rotate_right(8);
        x ^= C;
        x = x.wrapping_add(y.rotate_right(1));
        y ^= x.rotate_right(1);
        x ^= C;
        x = x.wrapping_add(y);
        y ^= x.rotate_right(15);
        x ^= C;
        x = x.wrapping_add(y.rotate_right(8));
        y ^= x;
        x ^= C;
        ((x as u32) << 16) | (y as u32)
    }

    fn fid(n: u32) -> FID {
        FID(n.to_le_bytes())
    }

    fn attach(inst: &mut TestInstance) {
        inst.server
            .version(&inst.next_meta(), 4096, inst.version.to_str().as_bytes())
            .unwrap();
        inst.server
            .attach(
                &inst.next_meta(),
                fid(0),
                fid(0xffffffff),
                b"foo",
                b"aname",
                None,
            )
            .unwrap();
    }

    fn lstat_dev_ino(inst: &TestInstance, path: &Path) -> Option<(u64, u64)> {
        let fd = rustix::fs::openat(
            rustix::fs::cwd(),
            inst.dir.path(),
            rustix::fs::OFlags::RDONLY,
            rustix::fs::Mode::from_bits(0o755).unwrap(),
        )
        .ok()?;
        let st = rustix::fs::statat(fd, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).ok()?;
        Some((st.st_dev as u64, st.st_ino as u64))
    }

    fn verify_file_is_path<F: FnOnce(&StdFileType) -> bool>(
        inst: &TestInstance,
        file: &Path,
        path: &Path,
        f: F,
    ) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        assert!(f(&meta.file_type()), "file is of correct type");
        let (dev, ino) = lstat_dev_ino(&inst, file).unwrap();
        assert_eq!((dev, ino), (meta.dev(), meta.ino()), "same file");
    }

    fn verify_dir(inst: &mut TestInstance, fid: FID, path: Option<&[u8]>) {
        if let Some(fidpath) = full_path_for_fid(inst, fid).as_ref() {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path.unwrap_or_default()));
            assert_ne!(
                fidpath.file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(
                fs::canonicalize(fidpath).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            match path {
                Some(path) => {
                    if path.is_empty() {
                        assert_eq!(full_path, inst.root, "path is root");
                    } else {
                        assert_eq!(*fidpath, full_path, "path is correct");
                    }
                }
                None => assert_eq!(full_path, inst.root, "path is root"),
            }
            verify_file_is_path(&inst, &fidpath, &full_path, |f| f.is_dir());
        } else {
            panic!("Not a directory");
        }
    }

    fn verify_file(inst: &mut TestInstance, fid: FID, path: &[u8]) {
        if let Some(fidpath) = full_path_for_fid(inst, fid).as_ref() {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(
                fidpath.file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(
                fs::canonicalize(fidpath).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            assert_eq!(*fidpath, full_path, "path is correct");
            verify_file_is_path(&inst, &fidpath, &full_path, |f| f.is_file());
        } else {
            panic!("Not a file");
        }
    }

    fn verify_symlink(inst: &mut TestInstance, fid: FID, path: &[u8], dest: &[u8]) {
        if let Some(fidpath) = full_path_for_fid(inst, fid) {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(
                fidpath.file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(fidpath, full_path, "path is correct");
            verify_file_is_path(&inst, &fidpath, &full_path, |f| f.is_symlink());
            let read_dest = fs::read_link(&full_path).unwrap();
            assert_eq!(
                read_dest.as_os_str().as_bytes(),
                dest,
                "destination is as expected"
            );
        } else {
            panic!("Not a symlink");
        }
    }

    fn full_path_for_fid(inst: &mut TestInstance, fid: FID) -> Option<PathBuf> {
        let meta = inst.next_meta();
        let meta = (&meta).into();
        let seq = inst.server.backend.pathname(&meta, fid.into()).ok()?;
        let mut path = inst.dir.path().to_owned();
        if seq.len() == 1 && seq[0] == b"/" {
            return Some(path);
        }
        for component in seq {
            path.push(OsStr::from_bytes(&component));
        }
        Some(path)
    }

    fn verify_closed(inst: &mut TestInstance, fid: FID) {
        let meta = inst.next_meta();
        let meta = (&meta).into();
        assert!(inst.server.backend.is_open(&meta, fid.into()).is_err());
    }

    fn create_fixtures(inst: &mut TestInstance) {
        attach(inst);
        verify_dir(inst, fid(0), None);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[])
            .unwrap();
        inst.server
            .create(
                &inst.next_meta(),
                fid(1),
                b"dir",
                FileType::DMDIR | FileType::from_bits(0o770).unwrap(),
                SimpleOpenMode::O_READ,
                None,
            )
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(inst, fid(1));
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir"])
            .unwrap();
        verify_dir(inst, fid(2), Some(b"dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(2),
                b"file",
                FileType::from_bits(0o660).unwrap(),
                SimpleOpenMode::O_RDWR,
                None,
            )
            .unwrap();
        verify_file(inst, fid(2), b"dir/file");
        let body: &[u8] = b"Hello, world!\n";
        assert_eq!(
            inst.server
                .write(&inst.next_meta(), fid(2), 0, body)
                .unwrap() as usize,
            body.len()
        );
        let mut actual = [0u8; 512];
        let size = inst
            .server
            .read(&inst.next_meta(), fid(2), 0, &mut actual)
            .unwrap() as usize;
        assert_eq!(body, &actual[0..size]);
        let size = inst
            .server
            .read(&inst.next_meta(), fid(2), 2, &mut actual)
            .unwrap() as usize;
        assert_eq!(&body[2..], &actual[0..size]);
        verify_file(inst, fid(2), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        verify_closed(inst, fid(2));
    }

    #[test]
    fn handles_arbitrary_fids() {
        for ver in &[
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            let mut inst = instance(*ver);
            create_fixtures(&mut inst);
            // We explicitly check that we don't rely on sequential FIDs.  That is the logical way
            // to implement this on the client side, but the server cannot rely on that.  Thus, we
            // verify that we don't try to do things like allocate sufficient memory to hold all
            // valid FIDs in an array (which we don't).
            let seq = (0..=u32::MAX).map(minialzette);
            for n in seq.take(100) {
                inst.server
                    .walk(&inst.next_meta(), fid(0), fid(n), &[b"dir"])
                    .unwrap();
                verify_dir(&mut inst, fid(n), Some(b"dir"));
                inst.server
                    .create(
                        &inst.next_meta(),
                        fid(n),
                        format!("{:08x}", n).as_bytes(),
                        FileType::from_bits(0o660).unwrap(),
                        SimpleOpenMode::O_RDWR,
                        None,
                    )
                    .unwrap();
            }
            let seq = (0..=u32::MAX).map(minialzette);
            for n in seq.take(100) {
                // We run a stat to verify that the FID is still valid.
                if *ver == ProtocolVersion::Linux {
                    let st = inst
                        .server
                        .getattr(&inst.next_meta(), fid(n), LinuxStatValidity::BASIC)
                        .unwrap();
                    assert_eq!(st.length, 0);
                } else {
                    let st = inst.server.stat(&inst.next_meta(), fid(n)).unwrap();
                    assert_eq!(st.name(), format!("{:08x}", n).as_bytes());
                }
                verify_file(&mut inst, fid(n), format!("dir/{:08x}", n).as_bytes());
                inst.server.clunk(&inst.next_meta(), fid(n)).unwrap();
            }
        }
    }

    fn read_directory_names(inst: &mut TestInstance, f: FID) -> HashSet<Vec<u8>> {
        let mut actual = HashSet::new();
        let mut buffer = [0u8; 512];
        match inst.version {
            ProtocolVersion::Original => {
                let mut offset = 0;
                loop {
                    let read = inst
                        .server
                        .read(&inst.next_meta(), f, offset, &mut buffer)
                        .unwrap();
                    if read == 0 {
                        break;
                    }
                    offset += read as u64;
                    let buf = &buffer[0..read as usize];
                    let mut bufoff = 0;
                    while bufoff != buf.len() {
                        let len = u16::from_le_bytes(buf[bufoff..bufoff + 2].try_into().unwrap());
                        let st =
                            PlainStat::from_bytes(len, &buf[bufoff..bufoff + (len as usize) + 2])
                                .unwrap();
                        actual.insert(st.name);
                        bufoff += 2 + len as usize;
                    }
                }
            }
            ProtocolVersion::Unix => {
                let mut offset = 0;
                loop {
                    let read = inst
                        .server
                        .read(&inst.next_meta(), f, offset, &mut buffer)
                        .unwrap();
                    if read == 0 {
                        break;
                    }
                    offset += read as u64;
                    let buf = &buffer[0..read as usize];
                    let mut bufoff = 0;
                    while bufoff != buf.len() {
                        let len = u16::from_le_bytes(buf[bufoff..bufoff + 2].try_into().unwrap());
                        let st =
                            UnixStat::from_bytes(len, &buf[bufoff..bufoff + (len as usize) + 2])
                                .unwrap();
                        actual.insert(st.name);
                        bufoff += 2 + len as usize;
                    }
                }
            }
            ProtocolVersion::Linux => {
                let mut offset = 0;
                loop {
                    let entries = inst
                        .server
                        .readdir(&inst.next_meta(), f, offset, buffer.len() as u32)
                        .unwrap();
                    if entries.is_empty() {
                        break;
                    }
                    offset = entries[entries.len() - 1].offset;
                    for entry in entries {
                        actual.insert(entry.name);
                    }
                }
            }
        }
        actual
    }

    #[test]
    fn readdir_remove() {
        for ver in &[
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            let mut inst = instance(*ver);
            create_fixtures(&mut inst);
            // We explicitly check that we don't rely on sequential FIDs.  That is the logical way
            // to implement this on the client side, but the server cannot rely on that.  Thus, we
            // verify that we don't try to do things like allocate sufficient memory to hold all
            // valid FIDs in an array (which we don't).
            let seq = (0..=u32::MAX).map(minialzette);
            let mut set = HashSet::new();
            for n in seq.take(100) {
                inst.server
                    .walk(&inst.next_meta(), fid(0), fid(n), &[b"dir"])
                    .unwrap();
                verify_dir(&mut inst, fid(n), Some(b"dir"));
                let path = format!("{:08x}", n).as_bytes().to_vec();
                inst.server
                    .create(
                        &inst.next_meta(),
                        fid(n),
                        &path,
                        FileType::from_bits(0o660).unwrap(),
                        SimpleOpenMode::O_RDWR,
                        None,
                    )
                    .unwrap();
                set.insert(path);
            }
            set.insert(b"file".to_vec());
            let f = fid(minialzette(1000));
            inst.server
                .walk(&inst.next_meta(), fid(0), f, &[b"dir"])
                .unwrap();
            match ver {
                ProtocolVersion::Original | ProtocolVersion::Unix => {
                    inst.server
                        .open(&inst.next_meta(), f, SimpleOpenMode::O_READ)
                        .unwrap();
                }
                ProtocolVersion::Linux => {
                    inst.server
                        .lopen(&inst.next_meta(), f, LinuxOpenMode::O_RDONLY)
                        .unwrap();
                }
            }
            let actual = read_directory_names(&mut inst, f);
            assert_eq!(actual, set);
            let seq = (0..=u32::MAX).map(minialzette);
            for n in seq.take(100) {
                // We run a stat to verify that the FID is still valid.
                if *ver == ProtocolVersion::Linux {
                    let st = inst
                        .server
                        .getattr(&inst.next_meta(), fid(n), LinuxStatValidity::BASIC)
                        .unwrap();
                    assert_eq!(st.length, 0);
                } else {
                    let st = inst.server.stat(&inst.next_meta(), fid(n)).unwrap();
                    assert_eq!(st.name(), format!("{:08x}", n).as_bytes());
                }
                verify_file(&mut inst, fid(n), format!("dir/{:08x}", n).as_bytes());
                inst.server.remove(&inst.next_meta(), fid(n)).unwrap();
            }
            let actual = read_directory_names(&mut inst, f);
            let mut expected = HashSet::new();
            expected.insert(b"file".to_vec());
            assert_eq!(actual, expected);
        }
    }

    // NetBSD fails this test with ENOSPC, suggesting that it might not support sparse files.
    #[cfg(not(target_os = "netbsd"))]
    #[test]
    fn truncate_64bit() {
        // This test assumes sparse files exist.
        for ver in &[
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            const SIZE: u64 = 4_294_967_296;
            let mut inst = instance(ProtocolVersion::Original);
            create_fixtures(&mut inst);

            let qids = inst
                .server
                .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
                .unwrap();
            // Only the size is changed.
            match ver {
                ProtocolVersion::Original => {
                    let ps = PlainStat {
                        size: u16::MAX,
                        kind: u16::MAX,
                        dev: u32::MAX,
                        qid: qids[1],
                        mode: u32::MAX,
                        atime: u32::MAX,
                        mtime: u32::MAX,
                        length: SIZE,
                        name: Default::default(),
                        uid: Default::default(),
                        gid: Default::default(),
                        muid: Default::default(),
                    };
                    inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
                    let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
                    assert_eq!(st.length(), 0x1_0000_0000);
                }
                ProtocolVersion::Unix => {
                    let ps = UnixStat {
                        size: u16::MAX,
                        kind: u16::MAX,
                        dev: u32::MAX,
                        qid: qids[1],
                        mode: u32::MAX,
                        atime: u32::MAX,
                        mtime: u32::MAX,
                        length: SIZE,
                        name: Default::default(),
                        uid: Default::default(),
                        gid: Default::default(),
                        muid: Default::default(),
                        extension: Default::default(),
                        nuid: u32::MAX,
                        ngid: u32::MAX,
                        nmuid: u32::MAX,
                    };
                    inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
                    let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
                    assert_eq!(st.length(), 0x1_0000_0000);
                }
                ProtocolVersion::Linux => {
                    inst.server
                        .setattr(
                            &inst.next_meta(),
                            fid(1),
                            None,
                            None,
                            None,
                            Some(SIZE),
                            None,
                            None,
                            false,
                            false,
                        )
                        .unwrap();
                    let st = inst
                        .server
                        .getattr(&inst.next_meta(), fid(1), LinuxStatValidity::BASIC)
                        .unwrap();
                    assert_eq!(st.length, 0x1_0000_0000);
                }
            }
            verify_file(&mut inst, fid(1), b"dir/file");
            inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
            verify_closed(&mut inst, fid(1));
        }
    }

    #[test]
    fn chmod_orig() {
        let mut inst = instance(ProtocolVersion::Original);
        create_fixtures(&mut inst);
        let qids = inst
            .server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        // Only the mode is changed.
        let ps = PlainStat {
            size: u16::MAX,
            kind: u16::MAX,
            dev: u32::MAX,
            qid: qids[1],
            mode: 0o755,
            atime: u32::MAX,
            mtime: u32::MAX,
            length: u64::MAX,
            name: Default::default(),
            uid: Default::default(),
            gid: Default::default(),
            muid: Default::default(),
        };
        inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
        let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(st.mode().unwrap().bits() & 0o777, 0o755);
        verify_file(&mut inst, fid(1), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn chmod_unix() {
        let mut inst = instance(ProtocolVersion::Unix);
        create_fixtures(&mut inst);
        let qids = inst
            .server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        // Only the mode is changed.
        let ps = UnixStat {
            size: u16::MAX,
            kind: u16::MAX,
            dev: u32::MAX,
            qid: qids[1],
            mode: 0o755,
            atime: u32::MAX,
            mtime: u32::MAX,
            length: u64::MAX,
            name: Default::default(),
            uid: Default::default(),
            gid: Default::default(),
            muid: Default::default(),
            extension: Default::default(),
            nuid: u32::MAX,
            ngid: u32::MAX,
            nmuid: u32::MAX,
        };
        inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
        let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(st.mode().unwrap().bits() & 0o777, 0o755);
        verify_file(&mut inst, fid(1), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn chmod_linux() {
        let mut inst = instance(ProtocolVersion::Unix);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        inst.server
            .setattr(
                &inst.next_meta(),
                fid(1),
                Some((LinuxFileType::S_IFREG | LinuxFileType::from_bits(0o755).unwrap()).bits()),
                None,
                None,
                None,
                None,
                None,
                false,
                false,
            )
            .unwrap();
        let st = inst
            .server
            .getattr(&inst.next_meta(), fid(1), LinuxStatValidity::BASIC)
            .unwrap();
        assert_eq!(st.mode & 0o777, 0o755);
        verify_file(&mut inst, fid(1), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn escape() {
        for ver in &[
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            let mut inst = instance(*ver);
            create_fixtures(&mut inst);
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
                .unwrap();
            verify_dir(&mut inst, fid(1), Some(b"dir"));
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(2), &[b".."])
                .unwrap();
            verify_dir(&mut inst, fid(2), Some(b""));
            inst.server
                .walk(&inst.next_meta(), fid(1), fid(3), &[b"..", b".."])
                .unwrap();
            verify_dir(&mut inst, fid(3), Some(b""));
        }
    }

    #[test]
    fn escape_unix() {
        let mut inst = instance(ProtocolVersion::Unix);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(1),
                b"nested-dir",
                FileType::DMDIR | FileType::from_bits(0o770).unwrap(),
                SimpleOpenMode::O_READ,
                None,
            )
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir/nested-dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(1),
                b"symlink",
                FileType::DMSYMLINK | FileType::from_bits(0o777).unwrap(),
                SimpleOpenMode::O_READ,
                Some(b"../../.."),
            )
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/nested-dir/symlink", b"../../..");
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"nested-dir"])
            .unwrap();
        inst.server
            .create(
                &inst.next_meta(),
                fid(2),
                b"symlink2",
                FileType::DMSYMLINK | FileType::from_bits(0o777).unwrap(),
                SimpleOpenMode::O_READ,
                Some(b"../.."),
            )
            .unwrap();
        assert_eq!(
            inst.server
                .walk(
                    &inst.next_meta(),
                    fid(0),
                    fid(3),
                    &[b"dir", b"nested-dir", b"symlink", b"foo"]
                )
                .unwrap()
                .len(),
            3
        );
        verify_closed(&mut inst, fid(3));
        assert_eq!(
            inst.server
                .walk(
                    &inst.next_meta(),
                    fid(0),
                    fid(4),
                    &[b"dir", b"nested-dir", b"symlink2", b"dir", b"..", b".."]
                )
                .unwrap()
                .len(),
            6
        );
        verify_dir(&mut inst, fid(4), Some(b""));
    }

    #[test]
    fn create_linux() {
        let mut inst = instance(ProtocolVersion::Linux);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .lcreate(&inst.next_meta(), fid(1), b"foo", 0, 0o600, u32::MAX)
            .unwrap();
        verify_file(&mut inst, fid(1), b"dir/foo");
    }

    #[test]
    fn remove_broken_symlink() {
        for ver in &[ProtocolVersion::Unix, ProtocolVersion::Linux] {
            let mut inst = instance(*ver);
            create_fixtures(&mut inst);
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
                .unwrap();
            if *ver == ProtocolVersion::Unix {
                inst.server
                    .walk(&inst.next_meta(), fid(1), fid(2), &[])
                    .unwrap();
                inst.server
                    .create(
                        &inst.next_meta(),
                        fid(2),
                        b"symlink",
                        FileType::DMSYMLINK | FileType::from_bits(0o777).unwrap(),
                        SimpleOpenMode::O_READ,
                        Some(b"/nonexistent"),
                    )
                    .unwrap();
                verify_symlink(&mut inst, fid(2), b"dir/symlink", b"/nonexistent");
            } else {
                inst.server
                    .symlink(
                        &inst.next_meta(),
                        fid(1),
                        b"symlink",
                        b"/nonexistent",
                        u32::MAX,
                    )
                    .unwrap();
                inst.server
                    .walk(&inst.next_meta(), fid(1), fid(2), &[b"symlink"])
                    .unwrap();
                verify_symlink(&mut inst, fid(2), b"dir/symlink", b"/nonexistent");
            }
            inst.server.remove(&inst.next_meta(), fid(2)).unwrap();
        }
    }

    #[test]
    fn open_remove_linux() {
        let mut inst = instance(ProtocolVersion::Linux);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        // This mode is what the Linux kernel passes us as of 6.0, so let's make sure we handle it
        // gracefully.
        inst.server
            .lopen(
                &inst.next_meta(),
                fid(1),
                LinuxOpenMode::from_bits(0x18800).unwrap(),
            )
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"file"])
            .unwrap();
        inst.server
            .lopen(
                &inst.next_meta(),
                fid(2),
                LinuxOpenMode::O_WRONLY
                    | LinuxOpenMode::O_CREAT
                    | LinuxOpenMode::O_NOCTTY
                    | LinuxOpenMode::O_LARGEFILE,
            )
            .unwrap();
        verify_file(&mut inst, fid(2), b"dir/file");
        inst.server
            .walk(&inst.next_meta(), fid(2), fid(3), &[])
            .unwrap();
        verify_file(&mut inst, fid(3), b"dir/file");
        inst.server.remove(&inst.next_meta(), fid(3)).unwrap();
        verify_closed(&mut inst, fid(3));
    }

    #[test]
    fn clone_as_directory() {
        let mut inst = instance(ProtocolVersion::Linux);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        // This mode is what the Linux kernel passes us as of 6.0, so let's make sure we handle it
        // gracefully.
        inst.server
            .lopen(
                &inst.next_meta(),
                fid(1),
                LinuxOpenMode::from_bits(0x18800).unwrap(),
            )
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .walk(&inst.next_meta(), fid(1), fid(2), &[])
            .unwrap();
        inst.server
            .lopen(
                &inst.next_meta(),
                fid(2),
                LinuxOpenMode::from_bits(0x18800).unwrap(),
            )
            .unwrap();
        verify_dir(&mut inst, fid(2), Some(b"dir"));
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
        verify_dir(&mut inst, fid(2), Some(b"dir"));
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        verify_closed(&mut inst, fid(2));
    }

    #[test]
    fn symlink_unix() {
        let mut inst = instance(ProtocolVersion::Unix);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        inst.server
            .create(
                &inst.next_meta(),
                fid(1),
                b"symlink",
                FileType::DMSYMLINK | FileType::from_bits(0o777).unwrap(),
                SimpleOpenMode::O_READ,
                Some(b"file"),
            )
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(st.extension().unwrap(), b"file");
        inst.server
            .open(
                &inst.next_meta(),
                fid(1),
                SimpleOpenMode::O_RDWR | SimpleOpenMode::O_TRUNC,
            )
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let message = b"This is a test.  This is only a test.\n";
        inst.server
            .write(&inst.next_meta(), fid(1), 0, message)
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        inst.server
            .open(&inst.next_meta(), fid(1), SimpleOpenMode::O_RDWR)
            .unwrap();
        let mut buf = vec![0u8; message.len()];
        inst.server
            .read(&inst.next_meta(), fid(1), 0, &mut buf)
            .unwrap();
        assert_eq!(buf, message);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"file"])
            .unwrap();
        let st = inst.server.stat(&inst.next_meta(), fid(2)).unwrap();
        assert_eq!(st.length(), message.len() as u64);
    }

    #[test]
    fn symlink_linux() {
        let mut inst = instance(ProtocolVersion::Linux);
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        inst.server
            .symlink(&inst.next_meta(), fid(1), b"symlink", b"file", 0)
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let dest = inst.server.readlink(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(dest, b"file");
        inst.server
            .lopen(
                &inst.next_meta(),
                fid(1),
                LinuxOpenMode::O_RDWR | LinuxOpenMode::O_TRUNC,
            )
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let message = b"This is a test.  This is only a test.\n";
        inst.server
            .write(&inst.next_meta(), fid(1), 0, message)
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        inst.server
            .lopen(&inst.next_meta(), fid(1), LinuxOpenMode::O_RDWR)
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let mut buf = vec![0u8; message.len()];
        inst.server
            .read(&inst.next_meta(), fid(1), 0, &mut buf)
            .unwrap();
        assert_eq!(buf, message);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"file"])
            .unwrap();
        let st = inst
            .server
            .getattr(&inst.next_meta(), fid(2), LinuxStatValidity::ALL)
            .unwrap();
        assert_eq!(st.length, message.len() as u64);
    }

    #[test]
    fn rename_orig() {
        let mut inst = instance(ProtocolVersion::Original);
        create_fixtures(&mut inst);
        let qids = inst
            .server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        // Only the name is changed.
        let ps = PlainStat {
            size: u16::MAX,
            kind: u16::MAX,
            dev: u32::MAX,
            qid: qids[1],
            mode: u32::MAX,
            atime: u32::MAX,
            mtime: u32::MAX,
            length: u64::MAX,
            name: b"foo".to_vec(),
            uid: Default::default(),
            gid: Default::default(),
            muid: Default::default(),
        };
        inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
        let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(st.name(), b"foo");
        verify_file(&mut inst, fid(1), b"dir/foo");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn rename_unix() {
        let mut inst = instance(ProtocolVersion::Original);
        create_fixtures(&mut inst);
        let qids = inst
            .server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        // Only the name is changed.
        let ps = UnixStat {
            size: u16::MAX,
            kind: u16::MAX,
            dev: u32::MAX,
            qid: qids[1],
            mode: u32::MAX,
            atime: u32::MAX,
            mtime: u32::MAX,
            length: u64::MAX,
            name: b"foo".to_vec(),
            extension: Default::default(),
            uid: Default::default(),
            gid: Default::default(),
            muid: Default::default(),
            nuid: u32::MAX,
            ngid: u32::MAX,
            nmuid: u32::MAX,
        };
        inst.server.wstat(&inst.next_meta(), fid(1), &ps).unwrap();
        let st = inst.server.stat(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(st.name(), b"foo");
        verify_file(&mut inst, fid(1), b"dir/foo");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn rename_linux() {
        for use_renameat in &[true, false] {
            let mut inst = instance(ProtocolVersion::Linux);
            create_fixtures(&mut inst);
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
                .unwrap();
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"file"])
                .unwrap();
            inst.server
                .rename(&inst.next_meta(), fid(2), fid(1), b"foo")
                .unwrap();
            verify_file(&mut inst, fid(2), b"dir/foo");
            inst.server
                .mkdir(&inst.next_meta(), fid(0), b"other-dir", 0o770, u32::MAX)
                .unwrap();
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(3), &[b"other-dir"])
                .unwrap();
            verify_dir(&mut inst, fid(3), Some(b"other-dir"));
            inst.server
                .mkdir(&inst.next_meta(), fid(3), b"nested-dir", 0o770, u32::MAX)
                .unwrap();
            inst.server
                .walk(&inst.next_meta(), fid(3), fid(4), &[b"nested-dir"])
                .unwrap();
            verify_dir(&mut inst, fid(4), Some(b"other-dir/nested-dir"));
            if *use_renameat {
                inst.server
                    .renameat(&inst.next_meta(), fid(1), b"foo", fid(4), b"baz")
                    .unwrap();
                inst.server
                    .walk(
                        &inst.next_meta(),
                        fid(0),
                        fid(5),
                        &[b"other-dir", b"nested-dir", b"baz"],
                    )
                    .unwrap();
                verify_file(&mut inst, fid(5), b"other-dir/nested-dir/baz");
            } else {
                inst.server
                    .rename(&inst.next_meta(), fid(2), fid(4), b"baz")
                    .unwrap();
                verify_file(&mut inst, fid(2), b"other-dir/nested-dir/baz");
            }
            inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
            verify_closed(&mut inst, fid(1));
            inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
            verify_closed(&mut inst, fid(2));
            inst.server.clunk(&inst.next_meta(), fid(3)).unwrap();
            verify_closed(&mut inst, fid(3));
            inst.server.clunk(&inst.next_meta(), fid(4)).unwrap();
            verify_closed(&mut inst, fid(4));
        }
    }

    #[test]
    fn files_and_directories_std() {
        for ver in &[ProtocolVersion::Original, ProtocolVersion::Unix] {
            let mut inst = instance(*ver);
            attach(&mut inst);
            verify_dir(&mut inst, fid(0), None);
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(1), &[])
                .unwrap();
            inst.server
                .create(
                    &inst.next_meta(),
                    fid(1),
                    b"dir",
                    FileType::DMDIR | FileType::from_bits(0o770).unwrap(),
                    SimpleOpenMode::O_READ,
                    None,
                )
                .unwrap();
            inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
            verify_closed(&mut inst, fid(1));
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir"])
                .unwrap();
            verify_dir(&mut inst, fid(2), Some(b"dir"));
            inst.server
                .create(
                    &inst.next_meta(),
                    fid(2),
                    b"file",
                    FileType::from_bits(0o660).unwrap(),
                    SimpleOpenMode::O_RDWR,
                    None,
                )
                .unwrap();
            verify_file(&mut inst, fid(2), b"dir/file");
            let body: &[u8] = b"Hello, world!\n";
            assert_eq!(
                inst.server
                    .write(&inst.next_meta(), fid(2), 0, body)
                    .unwrap() as usize,
                body.len()
            );
            let mut actual = [0u8; 512];
            let size = inst
                .server
                .read(&inst.next_meta(), fid(2), 0, &mut actual)
                .unwrap() as usize;
            assert_eq!(body, &actual[0..size]);
            let size = inst
                .server
                .read(&inst.next_meta(), fid(2), 2, &mut actual)
                .unwrap() as usize;
            assert_eq!(&body[2..], &actual[0..size]);
            verify_file(&mut inst, fid(2), b"dir/file");
            inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
            verify_closed(&mut inst, fid(2));
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(3), &[b"dir"])
                .unwrap();
            verify_dir(&mut inst, fid(3), Some(b"dir"));
            let type_bits = FileType::DMDIR
                | FileType::DMSYMLINK
                | FileType::DMDEVICE
                | FileType::DMNAMEDPIPE
                | FileType::DMSOCKET;
            let setid_bits = FileType::DMSETUID | FileType::DMSETGID;
            let st = inst.server.stat(&inst.next_meta(), fid(3)).unwrap();
            assert_eq!(st.name(), b"dir");
            assert_eq!(st.mode().unwrap() & type_bits, FileType::DMDIR);
            assert_eq!(st.mode().unwrap() & setid_bits, FileType::empty());
            inst.server.clunk(&inst.next_meta(), fid(3)).unwrap();
            verify_closed(&mut inst, fid(3));
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(4), &[b"dir", b"file"])
                .unwrap();
            verify_file(&mut inst, fid(4), b"dir/file");
            let st = inst.server.stat(&inst.next_meta(), fid(4)).unwrap();
            assert_eq!(st.name(), b"file");
            assert_eq!(st.mode().unwrap() & type_bits, FileType::empty());
            assert_eq!(st.mode().unwrap() & setid_bits, FileType::empty());
            inst.server.clunk(&inst.next_meta(), fid(4)).unwrap();
            verify_closed(&mut inst, fid(4));
        }
    }

    #[test]
    fn files_and_directories_linux() {
        let mut inst = instance(ProtocolVersion::Linux);
        attach(&mut inst);
        verify_dir(&mut inst, fid(0), None);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[])
            .unwrap();
        inst.server
            .mkdir(&inst.next_meta(), fid(1), b"dir", 0o770, u32::MAX)
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(2), Some(b"dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(2),
                b"file",
                FileType::from_bits(0o660).unwrap(),
                SimpleOpenMode::O_RDWR,
                None,
            )
            .unwrap();
        verify_file(&mut inst, fid(2), b"dir/file");
        let body: &[u8] = b"Hello, world!\n";
        assert_eq!(
            inst.server
                .write(&inst.next_meta(), fid(2), 0, body)
                .unwrap() as usize,
            body.len()
        );
        let mut actual = [0u8; 512];
        let size = inst
            .server
            .read(&inst.next_meta(), fid(2), 0, &mut actual)
            .unwrap() as usize;
        assert_eq!(body, &actual[0..size]);
        let size = inst
            .server
            .read(&inst.next_meta(), fid(2), 2, &mut actual)
            .unwrap() as usize;
        assert_eq!(&body[2..], &actual[0..size]);
        verify_file(&mut inst, fid(2), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        verify_closed(&mut inst, fid(2));
    }
}
