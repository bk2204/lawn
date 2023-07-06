use crate::server::implementation::{Metadata, Serializer};
use bitflags::bitflags;
use lawn_constants::logger::{AsLogStr, Logger};
use lawn_constants::Error;
use lawn_fs::backend as fsbackend;
use lawn_fs::backend::Backend as FSBackend;
use num_derive::FromPrimitive;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fs;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[derive(Copy, Clone, FromPrimitive, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ProtocolTag {
    Init = 1,
    Version = 2,
    Open = 3,
    Close = 4,
    Read = 5,
    Write = 6,
    Lstat = 7,
    Fstat = 8,
    Setstat = 9,
    Fsetstat = 10,
    Opendir = 11,
    Readdir = 12,
    Remove = 13,
    Mkdir = 14,
    Rmdir = 15,
    Realpath = 16,
    Stat = 17,
    Rename = 18,
    Readlink = 19,
    Symlink = 20,
    Status = 101,
    Handle = 102,
    Data = 103,
    Name = 104,
    Attrs = 105,
    Extended = 200,
    ExtendedReply = 201,
}

#[derive(Copy, Clone, FromPrimitive, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProtocolVersion {
    V3 = 3,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Tag(pub u32);

/// The kind of SFTP extensions in use.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum ProtocolExtensions {
    OpenSSHPosixRenameV1,
    OpenSSHReversedSymlink,
    OpenSSHHardlinkV1,
    OpenSSHFsyncV1,
}

impl ProtocolExtensions {
    pub fn to_tuple(self) -> Option<(&'static [u8], &'static [u8])> {
        match self {
            Self::OpenSSHPosixRenameV1 => Some((b"posix-rename@openssh.com", b"1")),
            Self::OpenSSHReversedSymlink => None,
            Self::OpenSSHHardlinkV1 => Some((b"hardlink@openssh.com", b"1")),
            Self::OpenSSHFsyncV1 => Some((b"fsync@openssh.com", b"1")),
        }
    }

    pub fn from_tuple(name: &[u8], version: &[u8]) -> Option<Self> {
        match (name, version) {
            (b"posix-rename@openssh.com", b"1") => Some(Self::OpenSSHPosixRenameV1),
            (b"hardlink@openssh.com", b"1") => Some(Self::OpenSSHHardlinkV1),
            (b"fsync@openssh.com", b"1") => Some(Self::OpenSSHFsyncV1),
            _ => None,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::OpenSSHPosixRenameV1,
            Self::OpenSSHReversedSymlink,
            Self::OpenSSHHardlinkV1,
            Self::OpenSSHFsyncV1,
        ]
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone, FromPrimitive, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum SFTPErrorKind {
    EOF = 1,
    NoSuchFile = 2,
    PermissionDenied = 3,
    Failure = 4,
    BadMessage = 5,
    Unsupported = 8,
}

bitflags! {
    pub struct OpenFlags: u32 {
        const READ = 0x1;
        const WRITE = 0x2;
        const APPEND = 0x4;
        const CREAT = 0x8;
        const TRUNC = 0x10;
        const EXCL = 0x20;
    }

    pub struct AttributeFlags: u32 {
        const SIZE = 0x1;
        const UIDGID = 0x2;
        const PERMISSIONS = 0x4;
        const ACMODTIME = 0x8;
        const EXTENDED = 0x80000000;
    }
}

impl From<OpenFlags> for fsbackend::OpenMode {
    fn from(flags: OpenFlags) -> fsbackend::OpenMode {
        let mut result = match (flags & (OpenFlags::READ | OpenFlags::WRITE)).bits() {
            0x1 => fsbackend::OpenMode::O_RDONLY,
            0x2 => fsbackend::OpenMode::O_WRONLY,
            0x3 => fsbackend::OpenMode::O_RDWR,
            _ => fsbackend::OpenMode::O_RDONLY,
        };
        if flags.contains(OpenFlags::APPEND) {
            result |= fsbackend::OpenMode::O_APPEND;
        }
        if flags.contains(OpenFlags::CREAT) {
            result |= fsbackend::OpenMode::O_CREAT;
        }
        if flags.contains(OpenFlags::TRUNC) {
            result |= fsbackend::OpenMode::O_TRUNC;
        }
        if flags.contains(OpenFlags::EXCL) {
            result |= fsbackend::OpenMode::O_EXCL;
        }
        result
    }
}

#[derive(Clone, Default, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Attributes {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub extended: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Attributes {
    const BASIC_MAX_SIZE: usize = 4 + 8 + 4 + 4 + 4 + 4 + 4;
}

impl From<&fsbackend::Stat> for Attributes {
    fn from(st: &fsbackend::Stat) -> Attributes {
        Attributes {
            size: Some(st.length),
            uid: Some(st.uid),
            gid: Some(st.gid),
            permissions: Some(st.mode),
            atime: st.atime_sec.and_then(|st| st.try_into().ok()),
            mtime: st.mtime_sec.and_then(|st| st.try_into().ok()),
            extended: BTreeMap::new(),
        }
    }
}

impl From<fsbackend::Stat> for Attributes {
    fn from(st: fsbackend::Stat) -> Attributes {
        Attributes::from(&st)
    }
}

impl From<&fs::Metadata> for Attributes {
    #[cfg(unix)]
    fn from(st: &fs::Metadata) -> Attributes {
        use std::os::unix::fs::MetadataExt;
        Attributes {
            size: Some(st.len()),
            uid: Some(st.uid()),
            gid: Some(st.gid()),
            permissions: Some(st.mode()),
            atime: st
                .accessed()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| d.as_secs().try_into().ok()),
            mtime: st
                .modified()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| d.as_secs().try_into().ok()),
            extended: BTreeMap::new(),
        }
    }

    #[cfg(not(unix))]
    fn from(st: &fs::Metadata) -> Attributes {
        Attributes {
            size: Some(st.len()),
            uid: None,
            gid: None,
            permissions: Some(st.mode()),
            atime: st
                .accessed()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| d.as_secs().try_into().ok()),
            mtime: st
                .modified()
                .ok()
                .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
                .and_then(|d| d.as_secs().try_into().ok()),
            extended: BTreeMap::new(),
        }
    }
}

impl ProtocolResponse for Attributes {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error> {
        let mut flags = AttributeFlags::empty();
        if self.size.is_some() {
            flags |= AttributeFlags::SIZE;
        }
        if self.uid.is_some() && self.gid.is_some() {
            flags |= AttributeFlags::UIDGID;
        }
        if self.permissions.is_some() {
            flags |= AttributeFlags::PERMISSIONS;
        }
        if self.atime.is_some() && self.mtime.is_some() {
            flags |= AttributeFlags::ACMODTIME;
        }
        if !self.extended.is_empty() {
            flags |= AttributeFlags::EXTENDED;
        }
        ser.write_u32(flags.bits());
        if let Some(size) = self.size {
            ser.write_u64(size);
        }
        if let Some((uid, gid)) = self.uid.zip(self.gid) {
            ser.write_u32(uid);
            ser.write_u32(gid);
        }
        if let Some(perms) = self.permissions {
            ser.write_u32(perms);
        }
        if let Some((atime, mtime)) = self.atime.zip(self.mtime) {
            ser.write_u32(atime);
            ser.write_u32(mtime);
        }
        if !self.extended.is_empty() {
            ser.write_u32(self.extended.len() as u32);
            for (k, v) in self.extended.iter() {
                ser.write_string(k)?;
                ser.write_string(v)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SFTPError {
    kind: SFTPErrorKind,
    description: String,
}

impl SFTPError {
    pub fn new(kind: SFTPErrorKind, description: &str) -> Self {
        SFTPError {
            kind,
            description: description.to_owned(),
        }
    }
}

impl From<Error> for SFTPError {
    fn from(err: Error) -> SFTPError {
        // This mapping is roughly the one used by OpenSSH, with a few differences.
        let kind = match err {
            Error::EPERM | Error::EACCES | Error::EFAULT => SFTPErrorKind::PermissionDenied,
            Error::ENOENT | Error::ENOTDIR | Error::EBADF | Error::ELOOP => {
                SFTPErrorKind::NoSuchFile
            }
            Error::EOPNOTSUPP | Error::ENOSYS => SFTPErrorKind::Unsupported,
            Error::EBADMSG | Error::EINVAL | Error::ENAMETOOLONG => SFTPErrorKind::BadMessage,
            _ => SFTPErrorKind::Failure,
        };
        SFTPError {
            kind,
            description: format!("{}", err),
        }
    }
}

impl ProtocolResponse for SFTPError {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error> {
        ser.write_u32(self.kind as u32);
        ser.write_string(self.description.as_bytes())?;
        ser.write_string(b"en")?;
        Ok(())
    }
}

pub(crate) trait ProtocolResponse {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error>;
}

impl ProtocolResponse for () {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error> {
        ser.write_u32(0);
        ser.write_string(b"OK")?;
        ser.write_string(b"en")?;
        Ok(())
    }
}

pub struct NameResponse {
    filename: Vec<u8>,
    longname: Vec<u8>,
    attrs: Attributes,
}

impl ProtocolResponse for NameResponse {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error> {
        ser.write_string(&self.filename)?;
        ser.write_string(&self.longname)?;
        self.attrs.serialize(ser)?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Handle(pub u32);

impl ProtocolResponse for Handle {
    fn serialize(&self, ser: &mut Serializer) -> Result<(), Error> {
        ser.write_handle(*self);
        Ok(())
    }
}

impl From<Handle> for fsbackend::FID {
    fn from(h: Handle) -> fsbackend::FID {
        fsbackend::FID::new(h.0 as u64)
    }
}

struct TemporaryFID {
    backend: Arc<dyn FSBackend + Send + Sync + 'static>,
    fid: fsbackend::FID,
}

impl TemporaryFID {
    fn fid(&self) -> fsbackend::FID {
        self.fid
    }
}

impl Drop for TemporaryFID {
    fn drop(&mut self) {
        let meta = fsbackend::Metadata::new(
            fsbackend::Tag::new(u64::MAX),
            u64::MAX,
            fsbackend::ProtocolType::SFTP(fsbackend::SFTPType::V3, &[]),
            None,
            true,
        );
        let _ = self.backend.clunk(&meta, self.fid);
    }
}

pub struct Backend {
    logger: Arc<dyn Logger + Send + Sync>,
    backend: Arc<dyn FSBackend + Send + Sync + 'static>,
    tempfid: AtomicU32,
    handle: AtomicU32,
    dir_offsets: Mutex<HashMap<Handle, u64>>,
}

impl Backend {
    const ROOT_FID: fsbackend::FID = fsbackend::FID::new(2u64 << 32);

    pub fn new(
        logger: Arc<dyn Logger + Send + Sync>,
        backend: Arc<dyn FSBackend + Send + Sync + 'static>,
        uname: Option<&[u8]>,
        mount: &[u8],
    ) -> Result<Self, Error> {
        let meta = fsbackend::Metadata::new(
            fsbackend::Tag::new(u64::MAX),
            u64::MAX,
            fsbackend::ProtocolType::SFTP(fsbackend::SFTPType::V3, &[]),
            None,
            true,
        );
        backend.attach(
            &meta,
            Self::ROOT_FID,
            None,
            uname.unwrap_or_default(),
            mount,
            None,
        )?;
        Ok(Self {
            logger,
            backend,
            tempfid: AtomicU32::new(0),
            handle: AtomicU32::new(0),
            dir_offsets: Mutex::new(HashMap::new()),
        })
    }

    fn temp_fid(&self) -> TemporaryFID {
        let fid = self.tempfid.fetch_add(1, Ordering::AcqRel) as u64 | (1u64 << 32);
        TemporaryFID {
            backend: self.backend.clone(),
            fid: fsbackend::FID::new(fid),
        }
    }

    fn handle(&self) -> Handle {
        Handle(self.handle.fetch_add(1, Ordering::AcqRel))
    }

    fn components<'a>(&self, path: &'a [u8]) -> Vec<&'a [u8]> {
        let path = if path.starts_with(b"/") {
            &path[1..]
        } else {
            path
        };
        path.split(|x| *x == b'/').collect()
    }

    pub fn init(
        &self,
        ver: u32,
        _extensions: &BTreeMap<&[u8], &[u8]>,
    ) -> Result<(ProtocolVersion, BTreeSet<ProtocolExtensions>), Error> {
        // We send all the extensions we support here because sshfs doesn't send any from its side
        // but wants us to return all the ones we support anyway.
        let mut exts = ProtocolExtensions::all()
            .iter()
            .cloned()
            .filter(|pe| pe.to_tuple().is_some())
            .collect::<BTreeSet<_>>();
        if ver >= 3 {
            exts.insert(ProtocolExtensions::OpenSSHReversedSymlink);
            Ok((ProtocolVersion::V3, exts))
        } else {
            Err(Error::EOPNOTSUPP)
        }
    }

    pub fn open(
        &self,
        meta: &Metadata,
        filename: &[u8],
        flags: OpenFlags,
        attrs: &Attributes,
    ) -> Result<Handle, Error> {
        trace!(
            self.logger,
            "SFTP: open: flags {:?} attrs {:?} filename {}",
            flags,
            attrs,
            filename.as_log_str(),
        );
        let meta = meta.into();
        let handle = self.handle();
        let mut components = self.components(filename);
        if flags.contains(OpenFlags::CREAT) {
            let last = components.pop().ok_or(Error::EINVAL)?;
            let mode = fsbackend::FileType::from_bits(
                attrs.permissions.map(|p| p & 0o7777).unwrap_or(0o644),
            )
            .ok_or(Error::EINVAL)?;
            self.backend
                .resolve(&meta, Self::ROOT_FID, handle.into(), &components)?;
            self.backend.create(
                &meta,
                handle.into(),
                handle.into(),
                last,
                flags.into(),
                mode,
                attrs.gid,
            )?;
        } else {
            self.backend
                .resolve(&meta, Self::ROOT_FID, handle.into(), &components)?;
            self.backend.open(&meta, handle.into(), flags.into())?;
        }
        Ok(handle)
    }

    pub fn close(&self, meta: &Metadata, handle: Handle) -> Result<(), Error> {
        let meta = meta.into();
        let mut g = self.dir_offsets.lock().unwrap();
        g.remove(&handle);
        self.backend.clunk(&meta, handle.into())
    }

    pub fn read(
        &self,
        meta: &Metadata,
        handle: Handle,
        offset: u64,
        data: &mut [u8],
    ) -> Result<u32, Error> {
        let meta = meta.into();
        self.backend.read(&meta, handle.into(), offset, data)
    }

    pub fn write(
        &self,
        meta: &Metadata,
        handle: Handle,
        offset: u64,
        data: &[u8],
    ) -> Result<(), Error> {
        let meta = meta.into();
        let mut total = 0;
        loop {
            let res = self.backend.write(&meta, handle.into(), offset, data)? as usize;
            total += res;
            if total == data.len() {
                return Ok(());
            }
        }
    }

    pub fn remove(&self, meta: &Metadata, path: &[u8]) -> Result<(), Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        self.backend.remove(&meta, fid.fid())
    }

    pub fn rename(&self, meta: &Metadata, source: &[u8], dest: &[u8]) -> Result<(), Error> {
        // TODO: This should fail on an existing file.  Use link and remove.
        self.posix_rename(meta, source, dest)
    }

    pub fn posix_rename(&self, meta: &Metadata, source: &[u8], dest: &[u8]) -> Result<(), Error> {
        let meta = meta.into();
        let sfid = self.temp_fid();
        let dfid = self.temp_fid();
        let scomp = self.components(source);
        let mut dcomp = self.components(dest);
        let last = dcomp.pop().ok_or(Error::EINVAL)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, sfid.fid(), &scomp)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, dfid.fid(), &dcomp)?;
        self.backend.rename(&meta, sfid.fid(), dfid.fid(), last)
    }

    pub fn mkdir(&self, meta: &Metadata, path: &[u8], attrs: &Attributes) -> Result<(), Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let mut components = self.components(path);
        let last = components.pop().ok_or(Error::EINVAL)?;
        let mode =
            fsbackend::FileType::from_bits(attrs.permissions.map(|p| p & 0o7777).unwrap_or(0o755))
                .ok_or(Error::EINVAL)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        self.backend
            .mkdir(&meta, fid.fid(), last, mode, attrs.gid)?;
        Ok(())
    }

    pub fn rmdir(&self, meta: &Metadata, path: &[u8]) -> Result<(), Error> {
        self.remove(meta, path)
    }

    pub fn opendir(&self, meta: &Metadata, path: &[u8]) -> Result<Handle, Error> {
        let meta = meta.into();
        let handle = self.handle();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, handle.into(), &components)?;
        self.backend.open(
            &meta,
            handle.into(),
            fsbackend::OpenMode::O_RDONLY | fsbackend::OpenMode::O_DIRECTORY,
        )?;
        let mut g = self.dir_offsets.lock().unwrap();
        g.insert(handle, 0);
        Ok(handle)
    }

    pub fn readdir(&self, meta: &Metadata, handle: Handle) -> Result<Vec<NameResponse>, Error> {
        trace!(self.logger, "SFTP: readdir {:?}", handle);
        let max_size = meta.data.read().unwrap().max_size as u32;
        let meta = meta.into();
        let mut g = self.dir_offsets.lock().unwrap();
        let offset = *g.get(&handle).ok_or(Error::EBADF)?;
        trace!(
            self.logger,
            "SFTP: readdir: handle {:?} is ok; offset is {:08x}",
            handle,
            offset
        );
        let entries = self.backend.readdir(
            &meta,
            handle.into(),
            offset,
            max_size - 9 - 4,
            Box::new(|_| 1),
            Box::new(|_| Attributes::BASIC_MAX_SIZE),
        )?;
        if !entries.is_empty() {
            g.insert(handle, entries[entries.len() - 1].offset);
        }
        Ok(entries
            .into_iter()
            .map(|de| NameResponse {
                filename: de.name.clone(),
                longname: de.name,
                attrs: (&de.metadata).into(),
            })
            .collect())
    }

    pub fn fsync(&self, meta: &Metadata, handle: Handle) -> Result<(), Error> {
        let meta = meta.into();
        self.backend.fsync(&meta, handle.into());
        Ok(())
    }

    pub fn stat(&self, meta: &Metadata, path: &[u8]) -> Result<Attributes, Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let components = self.backend.realpath(&meta, fid.fid())?;
        let components = components.iter().map(|v| v.as_slice()).collect::<Vec<_>>();
        let fid = self.temp_fid();
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let st = self
            .backend
            .getattr(&meta, fid.fid(), fsbackend::StatValidity::BASIC)?;
        Ok(st.into())
    }

    pub fn lstat(&self, meta: &Metadata, path: &[u8]) -> Result<Attributes, Error> {
        trace!(self.logger, "SFTP: lstat {}", path.as_log_str());
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let st = self
            .backend
            .getattr(&meta, fid.fid(), fsbackend::StatValidity::BASIC)?;
        Ok(st.into())
    }

    pub fn fstat(&self, meta: &Metadata, handle: Handle) -> Result<Attributes, Error> {
        let meta = meta.into();
        let st = self
            .backend
            .getattr(&meta, handle.into(), fsbackend::StatValidity::BASIC)?;
        Ok(st.into())
    }

    pub fn setstat(&self, meta: &Metadata, path: &[u8], attr: &Attributes) -> Result<(), Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let components = self.backend.realpath(&meta, fid.fid())?;
        let components = components.iter().map(|v| v.as_slice()).collect::<Vec<_>>();
        let fid = self.temp_fid();
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let atime = attr
            .atime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        let mtime = attr
            .mtime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        self.backend.setattr(
            &meta,
            fid.fid(),
            attr.permissions,
            attr.uid,
            attr.gid,
            attr.size,
            atime,
            mtime,
            atime.is_some(),
            mtime.is_some(),
        )?;
        Ok(())
    }

    pub fn lsetstat(&self, meta: &Metadata, path: &[u8], attr: &Attributes) -> Result<(), Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let atime = attr
            .atime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        let mtime = attr
            .mtime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        self.backend.setattr(
            &meta,
            fid.fid(),
            attr.permissions,
            attr.uid,
            attr.gid,
            attr.size,
            atime,
            mtime,
            atime.is_some(),
            mtime.is_some(),
        )?;
        Ok(())
    }

    pub fn fsetstat(
        &self,
        meta: &Metadata,
        handle: Handle,
        attr: &Attributes,
    ) -> Result<(), Error> {
        let meta = meta.into();
        let atime = attr
            .atime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        let mtime = attr
            .mtime
            .map(|secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64));
        self.backend.setattr(
            &meta,
            handle.into(),
            attr.permissions,
            attr.uid,
            attr.gid,
            attr.size,
            atime,
            mtime,
            atime.is_some(),
            mtime.is_some(),
        )?;
        Ok(())
    }

    pub fn readlink(&self, meta: &Metadata, path: &[u8]) -> Result<NameResponse, Error> {
        let meta = meta.into();
        let fid = self.temp_fid();
        let components = self.components(path);
        self.backend
            .walk(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let dest = self.backend.readlink(&meta, fid.fid())?;
        Ok(NameResponse {
            filename: dest.clone(),
            longname: dest,
            attrs: Attributes::default(),
        })
    }

    pub fn symlink(
        &self,
        meta: &Metadata,
        linkpath: &[u8],
        targetpath: &[u8],
    ) -> Result<(), Error> {
        let (linkpath, targetpath) = if meta
            .protocol_data()
            .read()
            .unwrap()
            .extensions
            .contains(&ProtocolExtensions::OpenSSHReversedSymlink)
        {
            (targetpath, linkpath)
        } else {
            (linkpath, targetpath)
        };
        let meta = meta.into();
        let fid = self.temp_fid();
        let mut components = self.components(linkpath);
        let last = components.pop().ok_or(Error::EINVAL)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        self.backend
            .symlink(&meta, fid.fid(), last, targetpath, None)?;
        Ok(())
    }

    pub fn link(&self, meta: &Metadata, source: &[u8], dest: &[u8]) -> Result<(), Error> {
        let meta = meta.into();
        let sfid = self.temp_fid();
        let dfid = self.temp_fid();
        let scomp = self.components(source);
        let mut dcomp = self.components(dest);
        let last = dcomp.pop().ok_or(Error::EINVAL)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, sfid.fid(), &scomp)?;
        self.backend
            .resolve(&meta, Self::ROOT_FID, dfid.fid(), &dcomp)?;
        self.backend.rename(&meta, dfid.fid(), sfid.fid(), last)
    }

    pub fn realpath(&self, meta: &Metadata, path: &[u8]) -> Result<NameResponse, Error> {
        let meta = meta.into();
        let components = self.components(path);
        let fid = self.temp_fid();
        self.backend
            .resolve(&meta, Self::ROOT_FID, fid.fid(), &components)?;
        let rcomponents = self.backend.realpath(&meta, fid.fid())?;
        let mut result = vec![b'/'];
        result.extend(rcomponents.join(b"/" as &[u8]));
        Ok(NameResponse {
            filename: result.clone(),
            longname: result,
            attrs: Attributes::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Attributes, Backend, FSBackend, Handle, Metadata, OpenFlags, ProtocolExtensions,
        ProtocolTag, ProtocolVersion, Tag,
    };
    use crate::server::implementation::ProtocolData;
    use lawn_constants::logger::{LogFormat, LogLevel};
    use lawn_constants::Error;
    use lawn_fs::auth::{AuthenticationInfo, Authenticator, AuthenticatorHandle};
    use std::collections::{BTreeMap, BTreeSet, HashSet};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, RwLock};
    use tempfile::TempDir;

    /// A permutation on the 64-bit integers.
    ///
    /// This is the Alzette ARX-box with the constant fixed to c_0 (0xb7e15162).  The exact
    /// algorithm doesn't matter very much, but this one provides a good distribution.
    fn alzette(n: u64) -> u64 {
        const C: u32 = 0xb7e15162;
        let (mut x, mut y) = ((n >> 32) as u32, n as u32);
        x = x.wrapping_add(y.rotate_right(31));
        y ^= x.rotate_right(24);
        x ^= C;
        x = x.wrapping_add(y.rotate_right(17));
        y ^= x.rotate_right(17);
        x ^= C;
        x = x.wrapping_add(y);
        y ^= x.rotate_right(31);
        x ^= C;
        x = x.wrapping_add(y.rotate_right(24));
        y ^= x.rotate_right(16);
        x ^= C;
        ((x as u64) << 32) | (y as u64)
    }

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

    pub struct Auther {
        user: Vec<u8>,
        dir: Vec<u8>,
    }

    impl Authenticator for Auther {
        fn create(
            &self,
            _metadata: &lawn_fs::backend::Metadata,
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

    type Server = Backend;

    #[allow(dead_code)]
    struct TestInstance {
        dir: TempDir,
        root: PathBuf,
        server: Server,
        backend: Arc<dyn FSBackend + Send + Sync + 'static>,
        tag: Mutex<u32>,
        pdata: Arc<RwLock<ProtocolData>>,
    }

    impl TestInstance {
        fn next_meta(&self, msg: ProtocolTag) -> Metadata {
            let mut g = self.tag.lock().unwrap();
            let tag = *g;
            *g += 1;
            Metadata {
                data: self.pdata.clone(),
                ver: self.pdata.read().unwrap().ver,
                tag: Tag(tag),
                msg,
            }
        }
    }

    fn instance(ver: ProtocolVersion, extensions: Option<&[ProtocolExtensions]>) -> TestInstance {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let logger = Arc::new(Logger {});
        let fsbackend = Arc::new(lawn_fs::backend::libc::LibcBackend::new(
            logger.clone(),
            Arc::new(Auther {
                user: "foo".into(),
                dir: dir.path().as_os_str().as_bytes().into(),
            }),
            1024 * 1024,
        ));
        TestInstance {
            backend: fsbackend.clone(),
            server: Server::new(logger.clone(), fsbackend, Some(b"foo"), b"mount").unwrap(),
            dir,
            root,
            tag: Mutex::new(0),
            pdata: Arc::new(RwLock::new(ProtocolData {
                ver,
                extensions: extensions.unwrap_or_default().iter().cloned().collect(),
                max_size: 1024 * 1024,
            })),
        }
    }

    fn instance_with_init() -> TestInstance {
        let inst = instance(ProtocolVersion::V3, None);
        let result = inst.server.init(3, &BTreeMap::new()).unwrap();
        let set: BTreeSet<_> = ProtocolExtensions::all().iter().cloned().collect();
        assert_eq!(
            result,
            (ProtocolVersion::V3, set),
            "instance inited successfully"
        );
        inst
    }

    fn attributes_from_perm(mode: u32) -> Attributes {
        Attributes {
            permissions: Some(mode & 0o7777),
            ..Default::default()
        }
    }

    fn create_fixtures(inst: &mut TestInstance) {
        inst.server
            .mkdir(
                &inst.next_meta(ProtocolTag::Mkdir),
                b"/dir",
                &attributes_from_perm(0o770),
            )
            .unwrap();
        let handle = inst
            .server
            .open(
                &inst.next_meta(ProtocolTag::Open),
                b"/dir/file",
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREAT,
                &attributes_from_perm(0o660),
            )
            .unwrap();
        let body: &[u8] = b"Hello, world!\n";
        inst.server
            .write(&inst.next_meta(ProtocolTag::Write), handle, 0, body)
            .unwrap();
        let mut actual = [0u8; 512];
        let size = inst
            .server
            .read(&inst.next_meta(ProtocolTag::Read), handle, 2, &mut actual)
            .unwrap() as usize;
        assert_eq!(&body[2..], &actual[0..size]);
        inst.server
            .close(&inst.next_meta(ProtocolTag::Close), handle)
            .unwrap();
    }

    #[test]
    fn basic_fixtures() {
        let mut inst = instance_with_init();
        create_fixtures(&mut inst);
    }

    fn read_directory_names(inst: &mut TestInstance, handle: Handle) -> HashSet<Vec<u8>> {
        let mut actual = HashSet::new();
        loop {
            let entries = inst
                .server
                .readdir(&inst.next_meta(ProtocolTag::Readdir), handle)
                .unwrap();
            if entries.is_empty() {
                break;
            }
            actual.extend(entries.into_iter().map(|e| e.filename));
        }
        actual
    }

    #[test]
    fn readdir_remove() {
        let mut inst = instance_with_init();
        create_fixtures(&mut inst);

        let mut set = HashSet::new();
        let mut handles = BTreeMap::new();
        let seq = (0..=u64::MAX).map(alzette);
        for n in seq.take(100) {
            let path = format!("dir/{:016x}", n);
            let handle = inst
                .server
                .open(
                    &inst.next_meta(ProtocolTag::Open),
                    path.as_bytes(),
                    OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREAT,
                    &attributes_from_perm(0o660),
                )
                .unwrap();
            set.insert(format!("{:016x}", n).into_bytes());
            handles.insert(n, handle);
        }
        set.insert(b"file".to_vec());
        let handle = inst
            .server
            .opendir(&inst.next_meta(ProtocolTag::Opendir), b"/dir")
            .unwrap();
        let actual = read_directory_names(&mut inst, handle);
        inst.server
            .close(&inst.next_meta(ProtocolTag::Close), handle)
            .unwrap();
        assert_eq!(actual, set);
        let seq = (0..=u64::MAX).map(alzette);
        for n in seq.take(100) {
            let path = format!("/dir/{:016x}", n);
            inst.server
                .remove(&inst.next_meta(ProtocolTag::Remove), path.as_bytes())
                .unwrap();
            let st = inst
                .server
                .fstat(
                    &inst.next_meta(ProtocolTag::Fstat),
                    *handles.get(&n).unwrap(),
                )
                .unwrap();
            assert_eq!(st.size, Some(0));
            inst.server
                .close(&inst.next_meta(ProtocolTag::Close), handle)
                .unwrap();
        }
        let handle = inst
            .server
            .opendir(&inst.next_meta(ProtocolTag::Opendir), b"/dir")
            .unwrap();
        let actual = read_directory_names(&mut inst, handle);
        inst.server
            .close(&inst.next_meta(ProtocolTag::Close), handle)
            .unwrap();
        let mut expected = HashSet::new();
        expected.insert(b"file".to_vec());
        assert_eq!(actual, expected);
    }
}
