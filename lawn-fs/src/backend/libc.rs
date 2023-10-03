use super::{
    Backend, DirEntry, FileType, Lock, LockCommand, LockKind, LockStatus, Metadata, OpenMode,
    QIDKind, Result, Stat, StatValidity, Tag, FID, QID,
};
use crate::auth::{Authenticator, AuthenticatorHandle};
use flurry::HashMap;
use lawn_constants::logger::{AsLogStr, Logger};
use lawn_constants::Error;
use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{cwd, AtFlags, Mode, OFlags, Timestamps};
use rustix::process::{Gid, RawGid, RawUid, Uid};
use std::cmp;
use std::convert::TryInto;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::iter::Peekable;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct OpenFileID {
    dev: u64,
    ino: u64,
    file: Arc<OwnedFd>,
    full_path: PathBuf,
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

    fn file(&self) -> Option<Arc<OwnedFd>> {
        Some(self.file.clone())
    }

    fn full_path(&self) -> &Path {
        &self.full_path
    }

    fn full_path_bytes(&self) -> &[u8] {
        self.full_path.as_os_str().as_bytes()
    }

    fn qid_kind(&self) -> Result<QIDKind> {
        let md = rustix::fs::fstat(&*self.file)?;
        Ok(QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(
            md.st_mode,
        )))
    }
}

#[derive(Debug)]
struct FileID {
    dev: u64,
    ino: u64,
    full_path: PathBuf,
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

    fn file(&self) -> Option<Arc<OwnedFd>> {
        None
    }

    fn full_path(&self) -> &Path {
        &self.full_path
    }

    fn full_path_bytes(&self) -> &[u8] {
        self.full_path.as_os_str().as_bytes()
    }

    fn qid_kind(&self) -> Result<QIDKind> {
        let md = rustix::fs::statat(cwd(), &self.full_path, AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(
            md.st_mode,
        )))
    }
}

enum FIDKind {
    Open(OpenFileID),
    Closed(FileID),
    Auth(Box<dyn AuthenticatorHandle + Send + Sync>),
}

impl FIDKind {
    fn qid_kind(&self) -> Result<QIDKind> {
        match self {
            FIDKind::Open(f) => f.qid_kind(),
            FIDKind::Closed(f) => f.qid_kind(),
            FIDKind::Auth(_) => Ok(QIDKind::Authentication),
        }
    }
}

impl fmt::Debug for FIDKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::result::Result<(), fmt::Error> {
        match self {
            FIDKind::Open(fd) => f.debug_tuple("FIDKind::Open").field(fd).finish(),
            FIDKind::Closed(fd) => f.debug_tuple("FIDKind::Closed").field(fd).finish(),
            FIDKind::Auth(_) => f.debug_tuple("FIDKind::Auth").finish(),
        }
    }
}

trait MaybeIDInfo {
    fn id_info(&self) -> Option<&dyn IDInfo>;
}

impl MaybeIDInfo for FIDKind {
    fn id_info(&self) -> Option<&dyn IDInfo> {
        match self {
            FIDKind::Open(f) => Some(f),
            FIDKind::Closed(f) => Some(f),
            FIDKind::Auth(_) => None,
        }
    }
}

trait IDInfo {
    fn dev(&self) -> u64;
    fn ino(&self) -> u64;
    fn file(&self) -> Option<Arc<OwnedFd>>;
    fn full_path(&self) -> &Path;
    fn full_path_bytes(&self) -> &[u8];
    fn qid_kind(&self) -> Result<QIDKind>;
}

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

impl FromMetadata for Stat {
    fn from_metadata(meta: &fs::Metadata) -> Option<Self> {
        let mode = FileType::from_unix(meta.mode());
        Some(Self {
            qid: QID::new(QIDKind::Unknown, u64::MAX, u64::MAX),
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

struct WalkState<'a> {
    root: &'a [u8],
    component: &'a [u8],
    kind: QIDKind,
    full_path: PathBuf,
    next_full_path: PathBuf,
    dir: Option<Arc<OwnedFd>>,
    file: Option<Arc<OwnedFd>>,
    last: bool,
    dev: u64,
    ino: u64,
}

#[allow(clippy::type_complexity)]
pub struct LibcBackend {
    max_size: u32,
    fid: HashMap<FID, FIDKind>,
    dir_offsets: HashMap<FID, HashMap<u64, Option<Arc<Mutex<Peekable<fs::ReadDir>>>>>>,
    root: RwLock<Option<Vec<u8>>>,
    logger: Arc<dyn Logger + Send + Sync>,
    auth: Arc<dyn Authenticator + Send + Sync>,
}

impl LibcBackend {
    pub fn new(
        logger: Arc<dyn Logger + Send + Sync>,
        auth: Arc<dyn Authenticator + Send + Sync>,
        max_size: u32,
    ) -> LibcBackend {
        Self {
            max_size,
            fid: HashMap::new(),
            dir_offsets: HashMap::new(),
            root: RwLock::new(None),
            logger,
            auth,
        }
    }

    fn maybe_open_symlink(
        &self,
        full_path: &[u8],
        flags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
    ) -> Result<(PathBuf, OwnedFd)> {
        let mut full_path = PathBuf::from(OsString::from_vec(full_path.into()));
        for _ in 0..40 {
            trace!(
                self.logger,
                "FS open: resolving path to {}",
                full_path.display()
            );
            match rustix::fs::openat(
                cwd(),
                &full_path,
                flags | rustix::fs::OFlags::NOFOLLOW,
                mode,
            )
            .map_err(|e| e.into())
            {
                Ok(fd) => return Ok((full_path, fd)),
                Err(Error::ELOOP) | Err(Error::EMLINK) => {
                    let dest = fs::read_link(&full_path)?;
                    let mut full_dest = full_path.clone();
                    full_dest = full_dest.parent().unwrap().into();
                    full_dest.push(&dest);
                    let g = self.root.read().unwrap();
                    let root = g.as_deref().ok_or(Error::EACCES)?;
                    if !self.is_within(full_dest.as_os_str().as_bytes(), root) {
                        return Err(Error::EACCES);
                    }
                    full_path = full_dest;
                }
                Err(e) => return Err(e),
            }
        }
        Err(Error::ELOOP)
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::unnecessary_cast)]
    fn open_file(
        &self,
        full_path: &[u8],
        flags: rustix::fs::OFlags,
        mode: rustix::fs::Mode,
        saved_path: Option<&[u8]>,
    ) -> Result<FIDKind> {
        trace!(self.logger, "FS open: opening {}", full_path.as_log_str());
        let (full_path, fd) = self.maybe_open_symlink(full_path, flags, mode)?;
        trace!(
            self.logger,
            "FS open: opened {}, fd {}",
            full_path.display(),
            fd.as_raw_fd()
        );
        let metadata = rustix::fs::fstat(&fd)?;
        let full_path = match saved_path {
            Some(p) => PathBuf::from(OsStr::from_bytes(p)),
            None => full_path,
        };
        Ok(FIDKind::Open(OpenFileID {
            dev: metadata.st_dev as u64,
            ino: metadata.st_ino as u64,
            file: Arc::new(fd),
            full_path,
        }))
    }

    fn clone_with_mode(&self, f: &FIDKind, flags: OFlags, mode: Option<Mode>) -> Result<FIDKind> {
        let idi = f.id_info().ok_or(Error::EOPNOTSUPP)?;
        let (file, full_path): (Option<RawFd>, _) =
            (idi.file().map(|f| f.as_raw_fd()), idi.full_path_bytes());
        let has_multi_fd = cfg!(not(target_os = "freebsd"));
        let (fname, flags) = match (file, has_multi_fd) {
            // The kernel will not like it if we try to open /dev/fd with O_DIRECTORY in this case
            // because it's not really a directory.
            (Some(file), true) => (self.file_name(&file), flags.difference(OFlags::DIRECTORY)),
            _ => (full_path.to_vec(), flags),
        };
        self.open_file(
            &fname,
            flags,
            mode.unwrap_or(Mode::empty()),
            Some(full_path),
        )
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "macos"
    ))]
    fn file_name<F: AsRawFd>(&self, f: &F) -> Vec<u8> {
        let s = format!("/dev/fd/{}", f.as_raw_fd());
        s.into()
    }

    #[allow(clippy::unnecessary_cast)]
    fn fstatat_dev_ino(&self, f: BorrowedFd<'_>, path: &[u8], follow: bool) -> Result<(u64, u64)> {
        let st = if path.is_empty() {
            rustix::fs::fstat(f)?
        } else {
            let flags = if follow {
                rustix::fs::AtFlags::empty()
            } else {
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW
            };
            rustix::fs::statat(cwd(), path, flags)?
        };
        Ok((st.st_dev as u64, st.st_ino as u64))
    }

    #[allow(clippy::unnecessary_cast)]
    fn lstat_dev_ino(&self, path: &[u8]) -> Result<(u64, u64)> {
        let st = rustix::fs::statat(cwd(), path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        Ok((st.st_dev as u64, st.st_ino as u64))
    }

    fn do_open(&self, meta: &Metadata, fid: FID, flags: OFlags) -> Result<(QID, Option<u32>)> {
        let tg = self.fid.guard();
        match self.fid.get(&fid, &tg) {
            Some(e) => {
                let fk = self.clone_with_mode(e, flags, None)?;
                self.fid.remove(&fid, &tg);
                trace!(self.logger, "FS do_open; fid {:?} fidkind {:?}", fid, fk,);
                let qid = if meta.needs_valid_qid() {
                    let idi = fk.id_info().unwrap();
                    QID::new(idi.qid_kind()?, idi.dev(), idi.ino())
                } else {
                    QID::default()
                };
                self.fid.insert(fid, fk, &tg);
                Ok((qid, None))
            }
            None => Err(Error::EBADF),
        }
    }

    fn system_time_to_timespec(&self, t: Option<SystemTime>, set: bool) -> rustix::fs::Timespec {
        match (set, t) {
            (true, Some(t)) => match t.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(t) => rustix::fs::Timespec {
                    tv_sec: t.as_secs() as rustix::fs::Secs,
                    tv_nsec: t.subsec_nanos() as rustix::fs::Nsecs,
                },
                Err(e) => rustix::fs::Timespec {
                    tv_sec: -(e.duration().as_secs() as rustix::fs::Secs),
                    tv_nsec: e.duration().subsec_nanos() as rustix::fs::Nsecs,
                },
            },
            (true, None) => rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_NOW,
            },
            (false, _) => rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_OMIT,
            },
        }
    }

    /// Determine if the path is within the given root.
    ///
    /// Returns true if the path is within the given root and false if it is not.
    fn is_within(&self, path: &[u8], root: &[u8]) -> bool {
        match path.len().cmp(&root.len()) {
            cmp::Ordering::Less => false,
            cmp::Ordering::Equal => path == root,
            cmp::Ordering::Greater => path.starts_with(root) && path[root.len()] == b'/',
        }
    }

    fn assert_valid_path_component(&self, path: &[u8], dotdot_ok: bool) -> Result<()> {
        if path.contains(&b'/') || (path == b".." && !dotdot_ok) {
            Err(Error::EINVAL)
        } else {
            Ok(())
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn walk_one_non_parent(
        &self,
        m: &Metadata,
        dest: PathBuf,
        st: &'_ mut WalkState<'_>,
    ) -> Result<QID> {
        st.full_path = dest.clone();
        // If this is the last component, we don't need to try to open it since we're not walking a
        // directory.
        if st.last {
            let metadata = fs::symlink_metadata(&dest)?;
            let ft = QIDKind::from_metadata(&metadata);
            st.kind = ft;
            st.next_full_path = st.full_path.clone();
            st.file = None;
            st.dev = metadata.dev();
            st.ino = metadata.ino();
            return Ok(QID::new(ft, metadata.dev(), metadata.ino()));
        }
        match rustix::fs::openat(cwd(), &dest, OFlags::RDONLY | OFlags::NOFOLLOW, 0.into())
            .map_err(|e| e.into())
        {
            Ok(fd) => {
                // This is a file, directory, or something other than a symlink.
                let qid = if m.needs_valid_qid() {
                    let metadata = rustix::fs::fstat(&fd)?;
                    QID::new(
                        QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(
                            metadata.st_mode,
                        )),
                        metadata.st_dev as u64,
                        metadata.st_ino as u64,
                    )
                } else {
                    QID::default()
                };
                st.kind = qid.kind();
                st.next_full_path = st.full_path.clone();
                st.file = Some(Arc::new(fd));
                st.dev = qid.dev();
                st.ino = qid.ino();
                Ok(qid)
            }
            Err(Error::ELOOP) | Err(Error::EMLINK) => {
                // This is a symlink.  We will read the value and replace our location
                // with a new path.  This may point outside of the root, but if that's the
                // case, we will verify that the path is valid in the next iteration, if any.
                let link_dest = dest.read_link()?;
                let metadata = dest.symlink_metadata()?;
                st.next_full_path.push(link_dest);
                st.next_full_path = st.full_path.canonicalize()?;
                st.file = None;
                st.kind = QIDKind::Symlink;
                st.dev = metadata.dev();
                st.ino = metadata.ino();
                Ok(QID::new(QIDKind::Symlink, metadata.dev(), metadata.ino()))
            }
            Err(e) => {
                // This is something we can't access, but we can finish here.
                Err(e)
            }
        }
    }

    fn walk_one(&self, m: &Metadata, st: &'_ mut WalkState<'_>) -> Result<QID> {
        self.assert_valid_path_component(st.component, true)?;
        if st.component == b".." {
            if st.full_path.as_os_str().as_bytes() == st.root {
                // This is defined to be a no-op.
                let qid = if m.needs_valid_qid() {
                    let (dev, ino) = self.lstat_dev_ino(st.full_path.as_os_str().as_bytes())?;
                    QID::new(QIDKind::Directory, dev, ino)
                } else {
                    QID::default()
                };
                let file = match &st.dir {
                    Some(d) => d.clone(),
                    None => Arc::new(rustix::fs::openat(
                        cwd(),
                        st.root,
                        OFlags::RDONLY | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?),
                };
                st.kind = QIDKind::Directory;
                st.next_full_path = st.full_path.clone();
                st.file = Some(file);
                st.dev = qid.dev();
                st.ino = qid.ino();
                Ok(qid)
            } else {
                st.full_path.pop();
                if !self.is_within(st.full_path.as_os_str().as_bytes(), st.root) {
                    return Err(Error::EACCES);
                }
                self.walk_one_non_parent(m, st.full_path.clone(), st)
            }
        } else {
            if !self.is_within(st.full_path.as_os_str().as_bytes(), st.root) {
                return Err(Error::EACCES);
            }
            let mut dest = st.full_path.clone();
            dest.push(OsStr::from_bytes(st.component));
            self.walk_one_non_parent(m, dest, st)
        }
    }

    fn fill_direntry(&self, path: &Path, name: &[u8], offset: u64) -> Result<DirEntry> {
        let metadata = fs::symlink_metadata(path)?;
        let ft = metadata.file_type();
        let extension = if ft.is_symlink() {
            fs::read_link(path)
                .map(|p| p.into_os_string().into_vec())
                .ok()
        } else if ft.is_char_device() {
            let (maj, min) = major_minor(metadata.rdev());
            Some(format!("c {} {}", maj, min).into_bytes())
        } else if ft.is_block_device() {
            let (maj, min) = major_minor(metadata.rdev());
            Some(format!("b {} {}", maj, min).into_bytes())
        } else {
            None
        };
        Ok(DirEntry {
            // TODO: map to proper type.
            qid: QID::new(QIDKind::Regular, metadata.dev(), metadata.ino()),
            kind: 0,
            offset: offset + 1,
            name: name.to_vec(),
            extension,
            file_type: FileType::from_unix(metadata.mode()),
            size: metadata.size(),
            metadata,
        })
    }

    fn do_readdir(
        &self,
        fid: FID,
        offset: u64,
        count: u32,
        offsetf: Box<dyn FnMut(&DirEntry) -> usize>,
        lenf: Box<dyn FnMut(&DirEntry) -> usize>,
    ) -> Result<Vec<DirEntry>> {
        let mut countf = offsetf;
        let mut lenf = lenf;
        let max_size = std::cmp::min(count, self.max_size - 4 - 7) as usize;
        let fg = self.fid.guard();
        let idi = match self.fid.get(&fid, &fg) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let dg = self.dir_offsets.guard();
        let idg;
        let new;
        let iter = if offset == 0 {
            new = Arc::new(Mutex::new(fs::read_dir(idi.full_path())?.peekable()));
            &new
        } else {
            match self.dir_offsets.get(&fid, &dg) {
                Some(map) => {
                    idg = map.guard();
                    match map.remove(&offset, &idg) {
                        Some(Some(dir)) => dir,
                        Some(None) | None => return Ok(Vec::new()),
                    }
                }
                // TODO: create a new iterator and seek.
                None => return Err(Error::EINVAL),
            }
        };
        let mut offset = offset;
        let mut msg_size = 0;
        let mut mu = iter.lock().unwrap();
        let riter = mu.by_ref();
        let mut res = Vec::new();
        let mut last_entry = None;
        loop {
            let (len, count) = if let Some(de) = last_entry.take() {
                let _ = riter.next();
                let len = lenf(&de);
                let count = countf(&de);
                trace!(
                    self.logger,
                    "FS readdir; existing entry {}; {} bytes",
                    (&*de.name).as_log_str(),
                    len,
                );
                res.push(de);
                (len, count)
            } else {
                let entry = riter.next();
                let entry = match entry {
                    Some(entry) => entry,
                    None => break,
                };
                let entry = entry?;
                trace!(
                    self.logger,
                    "FS readdir; reading entry {}",
                    entry.file_name().as_bytes().as_log_str()
                );
                let mut path = idi.full_path().to_owned();
                path.push(entry.file_name());
                let de = self.fill_direntry(&path, entry.file_name().as_bytes(), offset)?;
                let len = lenf(&de);
                let count = countf(&de);
                trace!(self.logger, "FS readdir; entry: {} bytes", len);
                res.push(de);
                (len, count)
            };
            offset += count as u64;
            msg_size += len;
            trace!(
                self.logger,
                "FS readdir; offset is now {}; msg size is {}",
                offset,
                msg_size
            );
            if let Some(Ok(entry)) = riter.peek() {
                trace!(
                    self.logger,
                    "FS readdir; peeking entry {}",
                    entry.file_name().as_bytes().as_log_str()
                );
                let mut path = idi.full_path().to_owned();
                path.push(entry.file_name());
                let de = self.fill_direntry(&path, entry.file_name().as_bytes(), offset)?;
                let len = lenf(&de);
                trace!(self.logger, "FS readdir; entry: {} bytes", len,);
                last_entry = Some(de);
                if msg_size + len > max_size {
                    trace!(
                        self.logger,
                        "FS readdir; entry too large ({} > {})",
                        msg_size + len,
                        max_size
                    );
                    let offmap = match self.dir_offsets.try_insert(fid, HashMap::default(), &dg) {
                        Ok(map) => map,
                        Err(e) => e.current,
                    };
                    let og = offmap.guard();
                    offmap.insert(offset, Some(iter.clone()), &og);
                    return Ok(res);
                }
            }
        }
        let offmap = match self.dir_offsets.try_insert(fid, HashMap::default(), &dg) {
            Ok(map) => map,
            Err(e) => e.current,
        };
        let og = offmap.guard();
        offmap.insert(offset, None, &og);
        Ok(res)
    }
}

impl Backend for LibcBackend {
    fn auth(
        &self,
        meta: &Metadata,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let handle = self.auth.create(meta, uname, aname, nuname);
        let handle = FIDKind::Auth(handle);
        let qid = QID::new(QIDKind::Authentication, u64::MAX, afid.to_u64());
        {
            let g = self.fid.guard();
            if self.fid.try_insert(afid, handle, &g).is_err() {
                return Err(Error::EINVAL);
            };
        }
        Ok(qid)
    }

    #[allow(clippy::unnecessary_cast)]
    fn attach(
        &self,
        meta: &Metadata,
        fid: FID,
        afid: Option<FID>,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let file = {
            let handle;
            let g;
            trace!(self.logger, "FS attach: fid {:?} afid {:?}", fid, afid);
            let info = match afid {
                None => {
                    trace!(self.logger, "FS attach: using anonymous auth");
                    handle = self.auth.create(meta, uname, aname, nuname);
                    match handle.info() {
                        Some(info) => {
                            trace!(self.logger, "FS attach: anonymous auth OK");
                            info
                        }
                        None => {
                            trace!(self.logger, "FS attach: anonymous auth failed");
                            return Err(Error::EACCES);
                        }
                    }
                }
                Some(afid) => {
                    trace!(self.logger, "FS attach: using non-anonymous auth");
                    g = self.fid.guard();
                    let auth = match self.fid.get(&afid, &g) {
                        Some(FIDKind::Auth(a)) => a,
                        _ => return Err(Error::EBADF),
                    };
                    match auth.info() {
                        Some(info) => info,
                        None => return Err(Error::EACCES),
                    }
                }
            };
            // TODO: implement Display for byte strings.
            trace!(
                self.logger,
                "FS attach: uname {} user {} aname {} dir {} nuname {:?} id {:?}",
                hex::encode(uname),
                hex::encode(info.user()),
                hex::encode(aname),
                hex::encode(info.dir()),
                nuname,
                info.id()
            );
            let location = info.location();
            let location = fs::canonicalize(Path::new(OsStr::from_bytes(location)))?;
            let location = location.as_os_str().as_bytes();
            let file = self.open_file(location, OFlags::RDONLY, 0.into(), None)?;
            trace!(
                self.logger,
                "FS attach: mounting location \"{}\" as root: fid {:?}",
                location.as_log_str(),
                fid
            );
            *self.root.write().unwrap() = Some(location.to_vec());
            file
        };
        trace!(self.logger, "FS attach: mapping fid");
        let metadata = rustix::fs::fstat(&*file.id_info().unwrap().file().unwrap())?;
        let qid = QID::new(
            QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(metadata.st_mode)),
            metadata.st_dev as u64,
            metadata.st_ino as u64,
        );
        let g = self.fid.guard();
        match self.fid.try_insert(fid, file, &g) {
            Ok(_) => {
                trace!(self.logger, "FS attach: mapping fid OK");
                Ok(qid)
            }
            Err(_) => Err(Error::EBADF),
        }
    }

    fn clunk(&self, _meta: &Metadata, fid: FID) -> Result<()> {
        trace!(self.logger, "FS clunk: fid {:?}", fid);
        let g = self.fid.guard();
        let dg = self.dir_offsets.guard();
        self.fid.remove(&fid, &g);
        self.dir_offsets.remove(&fid, &dg);
        Ok(())
    }

    fn clunk_all(&self, _meta: &Metadata) -> Result<()> {
        let g = self.fid.guard();
        self.fid.clear(&g);
        let dg = self.dir_offsets.guard();
        self.dir_offsets.clear(&dg);
        Ok(())
    }

    fn flush(&self, _meta: &Metadata, _tag: Tag) -> Result<()> {
        Err(Error::ENOSYS)
    }

    fn open(&self, meta: &Metadata, fid: FID, mode: OpenMode) -> Result<(QID, Option<u32>)> {
        trace!(self.logger, "FS open: fid {:?} mode {:?}", fid, mode);
        self.do_open(meta, fid, mode.to_unix())
    }

    fn is_open(&self, _meta: &Metadata, fid: FID) -> Result<bool> {
        let g = self.fid.guard();
        match self.fid.get(&fid, &g) {
            Some(FIDKind::Open(_)) | Some(FIDKind::Auth(_)) => Ok(true),
            Some(FIDKind::Closed(_)) => Ok(false),
            None => Err(Error::EBADF),
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn create(
        &self,
        meta: &Metadata,
        fid: FID,
        newfid: FID,
        name: &[u8],
        lflags: OpenMode,
        mode: FileType,
        _gid: Option<u32>,
    ) -> Result<(QID, Option<u32>)> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let dir_path = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi.full_path(),
            _ => return Err(Error::ENOTDIR),
        };
        let mut full_path = dir_path.to_owned();
        full_path.push(OsStr::from_bytes(name));
        let mode = Mode::from_bits(mode.bits() as rustix::fs::RawMode).ok_or(Error::EINVAL)?;
        let flags = lflags & OpenMode::O_ACCMODE;
        let flags = match flags {
            OpenMode::O_RDWR => OFlags::RDWR,
            OpenMode::O_WRONLY => OFlags::WRONLY,
            OpenMode::O_RDONLY => OFlags::RDONLY,
            _ => return Err(Error::EINVAL),
        };
        let flags = flags | OFlags::CREATE;
        let file = self.open_file(full_path.as_os_str().as_bytes(), flags, mode, None)?;
        trace!(
            self.logger,
            "FS create: fid {:?} lflags {:?} flags {:?} mode {:?}",
            fid,
            lflags,
            flags,
            mode
        );
        let qid = if meta.needs_valid_qid() {
            let metadata = rustix::fs::fstat(&*file.id_info().unwrap().file().unwrap())?;
            QID::new(
                QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(metadata.st_mode)),
                metadata.st_dev as u64,
                metadata.st_ino as u64,
            )
        } else {
            QID::default()
        };
        self.fid.insert(newfid, file, &g);
        Ok((qid, None))
    }

    fn read(&self, _meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32> {
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi,
            _ => return Err(Error::EBADF),
        };
        match idi.file() {
            Some(fh) => match rustix::io::pread(&*fh, data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            None => Err(Error::EBADF),
        }
    }

    fn write(&self, _meta: &Metadata, fid: FID, offset: u64, data: &[u8]) -> Result<u32> {
        trace!(
            self.logger,
            "FS write: fid {:?} offset {} bytes {}",
            fid,
            offset,
            data.len()
        );
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        trace!(self.logger, "FS write: validated data");
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi,
            _ => return Err(Error::EBADF),
        };
        match idi.file() {
            Some(fd) => match rustix::io::pwrite(&*fd, data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            None => {
                trace!(self.logger, "FS write: no such descriptor");
                Err(Error::EBADF)
            }
        }
    }

    fn remove(&self, meta: &Metadata, fid: FID) -> Result<()> {
        trace!(self.logger, "FS remove: fid {:?}", fid);
        let g = self.fid.guard();
        match self.fid.get(&fid, &g) {
            Some(fk) => {
                let _ = self.clunk(meta, fid);
                let idi = match fk.id_info() {
                    Some(p) => p,
                    _ => return Err(Error::EOPNOTSUPP),
                };
                let full_path = idi.full_path();
                let ftk = idi.qid_kind()?;
                trace!(
                    self.logger,
                    "FS remove: kind {:?} path {:?}",
                    ftk,
                    full_path,
                );
                if ftk == QIDKind::Directory {
                    fs::remove_dir(full_path)?
                } else {
                    fs::remove_file(full_path)?
                }
                Ok(())
            }
            None => Err(Error::EBADF),
        }
    }

    fn fsync(&self, _meta: &Metadata, fid: FID) {
        let g = self.fid.guard();
        if let Some(FIDKind::Open(fh)) = self.fid.get(&fid, &g) {
            let _ = rustix::fs::fsync(&*fh.file);
        }
    }

    fn walk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<Vec<QID>> {
        trace!(
            self.logger,
            "FS walk: fid {:?} newfid {:?} components {}",
            fid,
            newfid,
            name.len()
        );
        let g = self.root.read().unwrap();
        let root = match &*g {
            Some(root) => root,
            None => return Err(Error::EACCES),
        };
        trace!(self.logger, "FS walk: found root");
        let g = self.fid.guard();
        let (file, full_path, dev, ino) = match self.fid.get(&fid, &g) {
            Some(FIDKind::Open(fh)) => (Some(fh.file.clone()), &*fh.full_path, fh.dev(), fh.ino()),
            Some(FIDKind::Closed(fh)) => (None, &*fh.full_path, fh.dev(), fh.ino()),
            _ => return Err(Error::EBADF),
        };
        let full_path = full_path.to_owned();
        std::mem::drop(g);
        if name.is_empty() {
            let g = self.fid.guard();
            match &file {
                Some(f) => self.fid.insert(
                    newfid,
                    FIDKind::Open(OpenFileID {
                        dev,
                        ino,
                        file: f.clone(),
                        full_path,
                    }),
                    &g,
                ),
                None => self.fid.insert(
                    newfid,
                    FIDKind::Closed(FileID {
                        dev,
                        ino,
                        full_path,
                    }),
                    &g,
                ),
            };
            return Ok(Vec::new());
        }
        // First, we stat the full path and the FD to make sure that they're still the same.  We
        // then use the full path to walk.  This prevents us from being tricked into walking out of
        // the root accidentally if someone moves or replaces directories.
        if let Some(file) = file.clone() {
            trace!(
                self.logger,
                "FS walk: verifying full path for fd {} path {}",
                file.as_raw_fd(),
                full_path.display(),
            );
            let fst = self.fstatat_dev_ino(file.as_fd(), b"", false)?;
            let lst = self.lstat_dev_ino(full_path.as_os_str().as_bytes())?;
            trace!(
                self.logger,
                "FS walk: verifying full path: fstatat {}/{} lstat {}/{}",
                fst.0,
                fst.1,
                lst.0,
                lst.1
            );
            if fst != lst {
                return Err(Error::EIO);
            }
        }
        trace!(self.logger, "FS walk: full path verified");
        let buf = [0u8; 0];
        let mut st = WalkState {
            root,
            component: &buf,
            dir: None,
            file,
            kind: QIDKind::Regular,
            next_full_path: full_path.clone(),
            full_path,
            last: false,
            dev,
            ino,
        };
        let mut result = Vec::new();
        for (i, component) in name.iter().enumerate() {
            let last = i == name.len() - 1;
            st.last = last;
            st.component = component;
            trace!(
                self.logger,
                "FS walk: walking component \"{}\"",
                component.as_log_str()
            );
            match (i, self.walk_one(meta, &mut st)) {
                (_, Ok(qid)) => result.push(qid),
                (0, Err(e)) => return Err(e),
                (_, Err(_)) => break,
            }
            if !last {
                st.full_path = st.next_full_path.clone();
                st.dir = st.file.clone();
                st.file = None;
            }
        }
        if result.len() == name.len() {
            let g = self.fid.guard();
            self.fid.insert(
                newfid,
                FIDKind::Closed(FileID {
                    dev,
                    ino,
                    full_path: st.full_path,
                }),
                &g,
            );
        }
        trace!(
            self.logger,
            "FS walk: walk completed, {} components",
            result.len()
        );
        Ok(result)
    }

    fn symlink(
        &self,
        _meta: &Metadata,
        fid: FID,
        name: &[u8],
        target: &[u8],
        _gid: Option<u32>,
    ) -> Result<QID> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let mut full_path = idi.full_path().to_owned();
        full_path.push(OsStr::from_bytes(name));
        rustix::fs::symlinkat(target, cwd(), &full_path)?;
        let meta = fs::symlink_metadata(&full_path)?;
        Ok(QID::new(QIDKind::Symlink, meta.dev(), meta.ino()))
    }

    #[cfg(target_os = "macos")]
    fn mknod(
        &self,
        _meta: &Metadata,
        _fid: FID,
        _name: &[u8],
        _mode: FileType,
        _major: u32,
        _minor: u32,
        _gid: Option<u32>,
    ) -> Result<QID> {
        Err(Error::EOPNOTSUPP)
    }

    #[cfg(not(target_os = "macos"))]
    fn mknod(
        &self,
        _meta: &Metadata,
        fid: FID,
        name: &[u8],
        mode: FileType,
        major: u32,
        minor: u32,
        _gid: Option<u32>,
    ) -> Result<QID> {
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let mut full_path = idi.full_path().to_owned();
        full_path.push(OsStr::from_bytes(name));
        let mode = mode.to_unix();
        rustix::fs::mknodat(
            cwd(),
            &full_path,
            rustix::fs::FileType::from_raw_mode(mode),
            rustix::fs::Mode::from_raw_mode(mode),
            rustix::fs::makedev(major, minor),
        )?;
        let meta = fs::symlink_metadata(&full_path)?;
        Ok(QID::new(QIDKind::Symlink, meta.dev(), meta.ino()))
    }

    fn rename(&self, _meta: &Metadata, fid: FID, dfid: FID, newname: &[u8]) -> Result<()> {
        self.assert_valid_path_component(newname, false)?;
        let g = self.fid.guard();
        trace!(self.logger, "FS rename: verifying IDs");
        let oldidi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "FS rename: verified fid {:?}", fid);
        let newidi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "FS rename: verified fid {:?}", dfid);
        let oldname = oldidi.full_path();
        trace!(self.logger, "FS rename: verified path info");
        let mut new_full_path = newidi.full_path().to_owned();
        new_full_path.push(OsStr::from_bytes(newname));
        fs::rename(oldname, &new_full_path)?;
        match self.fid.get(&fid, &g) {
            Some(FIDKind::Open(f)) => {
                self.fid.insert(
                    fid,
                    FIDKind::Open(OpenFileID {
                        dev: f.dev,
                        ino: f.ino,
                        file: f.file.clone(),
                        full_path: new_full_path,
                    }),
                    &g,
                );
            }
            Some(FIDKind::Closed(f)) => {
                self.fid.insert(
                    fid,
                    FIDKind::Closed(FileID {
                        dev: f.dev,
                        ino: f.ino,
                        full_path: new_full_path,
                    }),
                    &g,
                );
            }
            _ => return Err(Error::EIO),
        }
        Ok(())
    }

    fn readlink(&self, _meta: &Metadata, fid: FID) -> Result<Vec<u8>> {
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let dest = fs::read_link(idi.full_path())?.into_os_string().into_vec();
        Ok(dest)
    }

    #[allow(clippy::unnecessary_cast)]
    fn getattr(&self, _meta: &Metadata, fid: FID, mask: StatValidity) -> Result<Stat> {
        trace!(self.logger, "FS getattr: fid {:?} mask {:?}", fid, mask);
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        if let Some(fd) = idi.file() {
            let meta = rustix::fs::fstat(&*fd)?;
            let mut st = Stat::from_unix(&meta);
            let ft = QIDKind::from_filetype(rustix::fs::FileType::from_raw_mode(meta.st_mode));
            st.qid = QID::new(ft, meta.st_dev as u64, meta.st_ino as u64);
            return Ok(st);
        }
        let full_path = idi.full_path();
        let meta = fs::symlink_metadata(full_path)?;
        let ft = QIDKind::from_metadata(&meta);
        let mut st = Stat::from_metadata(&meta).ok_or(Error::EOVERFLOW)?;
        st.qid = QID::new(ft, meta.dev(), meta.ino());
        Ok(st)
    }

    fn setattr(
        &self,
        _meta: &Metadata,
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
            "FS setattr: fid {:?} mode {:?} uid {:?} gid {:?} size {:?} atime {:?}/{} mtime {:?}/{}",
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
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => {
                trace!(self.logger, "FS setattr: kind {:?}", idi.qid_kind());
                idi.id_info().ok_or(Error::EOPNOTSUPP)?
            }
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "FS setattr: verified fid");
        let file = idi.file();
        let full_path = idi.full_path();
        if let Some(mode) = mode {
            match &file {
                Some(f) => rustix::fs::fchmod(
                    f.as_fd(),
                    Mode::from_bits((mode & 0o7777) as rustix::fs::RawMode).ok_or(Error::EINVAL)?,
                )?,
                None => rustix::fs::chmodat(
                    cwd(),
                    full_path,
                    Mode::from_bits((mode & 0o7777) as rustix::fs::RawMode).ok_or(Error::EINVAL)?,
                )?,
            }
        }
        if uid.is_some() || gid.is_some() {
            match &file {
                Some(f) => rustix::fs::fchown(
                    f.as_fd(),
                    uid.map(|u| unsafe { Uid::from_raw(u as RawUid) }),
                    gid.map(|g| unsafe { Gid::from_raw(g as RawGid) }),
                )?,
                None => rustix::fs::chownat(
                    cwd(),
                    full_path,
                    uid.map(|u| unsafe { Uid::from_raw(u as RawUid) }),
                    gid.map(|g| unsafe { Gid::from_raw(g as RawGid) }),
                    AtFlags::SYMLINK_NOFOLLOW,
                )?,
            }
        }
        if let Some(size) = size {
            match &file {
                Some(f) => rustix::fs::ftruncate(f.as_fd(), size)?,
                None => {
                    let fd = rustix::fs::openat(
                        cwd(),
                        full_path,
                        OFlags::WRONLY | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )?;
                    rustix::fs::ftruncate(fd, size)?
                }
            };
        }
        if atime.is_some() || mtime.is_some() {
            let times = Timestamps {
                last_access: self.system_time_to_timespec(atime, set_atime),
                last_modification: self.system_time_to_timespec(mtime, set_mtime),
            };
            match &file {
                Some(f) => rustix::fs::futimens(f.as_fd(), &times)?,
                None => rustix::fs::utimensat(cwd(), full_path, &times, AtFlags::SYMLINK_NOFOLLOW)?,
            }
        }
        Ok(())
    }

    fn xattrwalk(&self, _meta: &Metadata, _fid: FID, _newfid: FID, _name: &[u8]) -> Result<u64> {
        // TODO: implement xattrs.
        Err(Error::EOPNOTSUPP)
    }

    fn xattrcreate(
        &self,
        _meta: &Metadata,
        _fid: FID,
        _name: &[u8],
        _size: u64,
        _flags: u32,
    ) -> Result<()> {
        // TODO: implement xattrs.
        Err(Error::EOPNOTSUPP)
    }

    fn readdir(
        &self,
        _meta: &Metadata,
        fid: FID,
        offset: u64,
        count: u32,
        offsetf: Box<dyn FnMut(&DirEntry) -> usize>,
        lenf: Box<dyn FnMut(&DirEntry) -> usize>,
    ) -> Result<Vec<DirEntry>> {
        self.do_readdir(fid, offset, count, offsetf, lenf)
    }

    fn resolve(&self, _meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<()> {
        trace!(self.logger, "FS resolve: fid {:?}", fid);
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let mut path = idi.full_path().to_owned();
        if name.is_empty() {
            let (dev, ino) = self.lstat_dev_ino(path.as_os_str().as_bytes())?;
            self.fid.insert(
                newfid,
                FIDKind::Closed(FileID {
                    dev,
                    ino,
                    full_path: path,
                }),
                &g,
            );
            return Ok(());
        }
        for component in &name[0..name.len() - 1] {
            self.assert_valid_path_component(component, true)?;
            let component = OsStr::from_bytes(component);
            path.push(component);
        }
        let mut path = std::fs::canonicalize(path)?;
        path.push(OsStr::from_bytes(name.last().unwrap()));
        let guard = self.root.read().unwrap();
        let root = guard.as_ref().ok_or(Error::EBADF)?;
        if !self.is_within(path.as_os_str().as_bytes(), root) {
            return Err(Error::EACCES);
        }
        let (dev, ino) = self.lstat_dev_ino(path.as_os_str().as_bytes())?;
        self.fid.insert(
            newfid,
            FIDKind::Closed(FileID {
                dev,
                ino,
                full_path: path,
            }),
            &g,
        );
        Ok(())
    }

    fn realpath(&self, _meta: &Metadata, fid: FID) -> Result<Vec<Vec<u8>>> {
        trace!(self.logger, "FS realpath: fid {:?}", fid,);
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let path = idi.full_path().to_owned();
        let path = std::fs::canonicalize(path)?;
        let g = self.root.read().unwrap();
        let root = (*g).as_ref().ok_or(Error::EBADF)?;
        if !self.is_within(path.as_os_str().as_bytes(), root) {
            return Err(Error::EACCES);
        }
        let path = path.as_os_str().as_bytes();
        if path.len() == root.len() {
            return Ok(vec![(b"/" as &[u8]).to_owned()]);
        }
        let truncated = &path[root.len()..];
        if truncated.is_empty() || truncated[0] != b'/' {
            // This should never happen.
            return Err(Error::EOPNOTSUPP);
        }
        Ok(truncated
            .split(|b| *b == b'/')
            .map(|bs| bs.to_owned())
            .collect())
    }

    fn pathname(&self, _meta: &Metadata, fid: FID) -> Result<Vec<Vec<u8>>> {
        trace!(self.logger, "FS pathname: fid {:?}", fid);
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let path = idi.full_path();
        let path = path.as_os_str().as_bytes();
        let g = self.root.read().unwrap();
        let root = (*g).as_ref().ok_or(Error::EBADF)?;
        if !self.is_within(path, root) {
            return Err(Error::EACCES);
        }
        if path.len() == root.len() {
            return Ok(vec![(b"/" as &[u8]).to_owned()]);
        }
        let path = &path[root.len()..];
        Ok(path.split(|b| *b == b'/').map(ToOwned::to_owned).collect())
    }

    fn lock(
        &self,
        _meta: &Metadata,
        _fid: FID,
        _kind: LockCommand,
        _flags: u32,
        _start: u64,
        _length: u64,
        _proc_id: u32,
        _client_id: &[u8],
    ) -> Result<LockStatus> {
        // TODO: implement locks.
        Err(Error::EOPNOTSUPP)
    }
    fn getlock(
        &self,
        _meta: &Metadata,
        _fid: FID,
        _kind: LockKind,
        _start: u64,
        _length: u64,
        _proc_id: u32,
        _client_id: &[u8],
    ) -> Result<Lock> {
        // TODO: implement locks.
        Err(Error::EOPNOTSUPP)
    }

    fn link(&self, _meta: &Metadata, dfid: FID, fid: FID, name: &[u8]) -> Result<()> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let didi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let mut dpath = didi.full_path().to_owned();
        dpath.push(OsStr::from_bytes(name));
        rustix::fs::linkat(cwd(), idi.full_path(), cwd(), &dpath, AtFlags::empty())?;
        Ok(())
    }

    fn mkdir(
        &self,
        meta: &Metadata,
        dfid: FID,
        name: &[u8],
        mode: FileType,
        _gid: Option<u32>,
    ) -> Result<QID> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let didi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let mut full_path = didi.full_path().to_owned();
        full_path.push(OsStr::from_bytes(name));
        rustix::fs::mkdirat(
            cwd(),
            &full_path,
            Mode::from_bits((mode.bits() & 0o7777) as rustix::fs::RawMode).ok_or(Error::EINVAL)?,
        )?;
        if meta.needs_valid_qid() {
            let meta = fs::symlink_metadata(&full_path)?;
            Ok(QID::new(QIDKind::Directory, meta.dev(), meta.ino()))
        } else {
            Ok(QID::default())
        }
    }

    fn renameat(
        &self,
        _meta: &Metadata,
        olddirfid: FID,
        oldname: &[u8],
        newdirfid: FID,
        newname: &[u8],
    ) -> Result<()> {
        trace!(
            self.logger,
            "FS renameat: {:?}/{} -> {:?}/{}",
            olddirfid,
            oldname.as_log_str(),
            newdirfid,
            newname.as_log_str()
        );
        self.assert_valid_path_component(oldname, false)?;
        self.assert_valid_path_component(newname, false)?;
        trace!(self.logger, "FS renameat: verifying IDs");
        let g = self.fid.guard();
        let oldidi = match self.fid.get(&olddirfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let newidi = match self.fid.get(&newdirfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let mut oldpath = oldidi.full_path().to_owned();
        let mut newpath = newidi.full_path().to_owned();
        trace!(
            self.logger,
            "FS renameat: verified fid {:?}: {}; fid {:?}: {}",
            olddirfid,
            oldpath.display(),
            newdirfid,
            newpath.display()
        );
        oldpath.push(OsStr::from_bytes(oldname));
        newpath.push(OsStr::from_bytes(newname));
        fs::rename(oldpath, newpath)?;
        Ok(())
    }

    fn unlinkat(&self, _meta: &Metadata, _dirfd: FID, _name: &[u8], _flags: u32) -> Result<()> {
        // TODO: implement unlinkat.
        Err(Error::EOPNOTSUPP)
    }
}

#[cfg(not(miri))]
#[cfg(test)]
mod tests {
    use super::{LibcBackend, MaybeIDInfo};
    use crate::auth::{AuthenticationInfo, Authenticator, AuthenticatorHandle};
    use crate::backend::{
        Backend, FileType, Metadata, OpenMode, Plan9Type, ProtocolType, StatValidity, Tag, FID,
    };
    use lawn_constants::logger::{LogFormat, LogLevel};
    use lawn_constants::Error;
    use rustix::fd::{AsFd, OwnedFd};
    use std::collections::HashSet;
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

    pub struct Auther {
        user: Vec<u8>,
        dir: Vec<u8>,
    }

    impl Authenticator for Auther {
        fn create(
            &self,
            _metadata: &Metadata,
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
        version: Box<ProtocolType<'static>>,
        server: Server,
        tag: Mutex<u16>,
    }

    impl TestInstance {
        fn next_meta<'a>(&'a self) -> Metadata<'a> {
            let mut g = self.tag.lock().unwrap();
            let tag = *g;
            *g += 1;
            Metadata {
                proto: *self.version,
                proto_extra: None,
                tag: Tag::new(tag as u64),
                command: 0,
                efficient: false,
            }
        }
    }

    fn plan9_protocol(proto: Plan9Type) -> Box<ProtocolType<'static>> {
        Box::new(ProtocolType::Plan9(proto))
    }

    fn instance(version: Box<ProtocolType<'static>>) -> TestInstance {
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        TestInstance {
            version,
            server: Server::new(
                Arc::new(Logger {}),
                Arc::new(Auther {
                    user: "foo".into(),
                    dir: dir.path().as_os_str().as_bytes().into(),
                }),
                1024 * 1024,
            ),
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
        FID::new(n as u64)
    }

    fn attach(inst: &mut TestInstance) {
        inst.server
            .attach(&inst.next_meta(), fid(0), None, b"foo", b"aname", None)
            .unwrap();
    }

    fn verify_file_is_path<F: FnOnce(&StdFileType) -> bool>(
        inst: &TestInstance,
        file: Option<Arc<OwnedFd>>,
        path: &Path,
        f: F,
    ) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        assert!(f(&meta.file_type()), "file is of correct type");
        if let Some(file) = file {
            let (dev, ino) = inst
                .server
                .fstatat_dev_ino(file.as_fd(), b"", false)
                .unwrap();
            assert_eq!((dev, ino), (meta.dev(), meta.ino()), "same file");
        }
    }

    fn verify_dir(inst: &mut TestInstance, fid: FID, path: Option<&[u8]>) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(idi) = entry.and_then(|e| e.id_info()) {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path.unwrap_or_default()));
            assert_ne!(
                idi.full_path().file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(
                fs::canonicalize(idi.full_path()).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            match path {
                Some(path) => {
                    if path.is_empty() {
                        assert_eq!(full_path, inst.root, "path is root");
                    } else {
                        assert_eq!(idi.full_path(), full_path, "path is correct");
                    }
                }
                None => assert_eq!(full_path, inst.root, "path is root"),
            }
            verify_file_is_path(&inst, idi.file(), &full_path, |f| f.is_dir());
        } else {
            panic!("Not a directory");
        }
    }

    fn verify_file(inst: &mut TestInstance, fid: FID, path: &[u8]) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(idi) = entry.and_then(|e| e.id_info()) {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(
                idi.full_path().file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(
                fs::canonicalize(idi.full_path()).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            assert_eq!(idi.full_path(), full_path, "path is correct");
            verify_file_is_path(&inst, idi.file(), &full_path, |f| f.is_file());
        } else {
            panic!("Not a file");
        }
    }

    fn verify_symlink(inst: &mut TestInstance, fid: FID, path: &[u8], dest: &[u8]) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(idi) = entry.and_then(|e| e.id_info()) {
            let mut full_path = inst.root.clone();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(
                idi.full_path().file_name().map(|n| n.as_bytes()),
                Some(b".." as &[u8]),
                "not dot-dot"
            );
            assert_eq!(idi.full_path(), &full_path, "full path is correct");
            assert_eq!(idi.full_path(), full_path, "path is correct");
            verify_file_is_path(&inst, None, &full_path, |f| f.is_symlink());
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

    fn verify_closed(inst: &mut TestInstance, fid: FID) {
        let g = inst.server.fid.guard();
        assert!(inst.server.fid.get(&fid, &g).is_none());
    }

    fn create_fixtures(inst: &mut TestInstance) {
        attach(inst);
        verify_dir(inst, fid(0), None);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[])
            .unwrap();
        inst.server
            .mkdir(
                &inst.next_meta(),
                fid(1),
                b"dir",
                FileType::from_bits(0o770).unwrap(),
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
                fid(2),
                b"file",
                OpenMode::O_RDWR,
                FileType::from_bits(0o660).unwrap(),
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
    fn is_within() {
        let inst = instance(plan9_protocol(Plan9Type::Original));
        assert!(inst.server.is_within(b"/tmp/foo", b"/tmp"));
        assert!(!inst.server.is_within(b"/dev/null", b"/tmp"));
        assert!(!inst.server.is_within(b"/tmp", b"/tmp/foo"));
        assert!(inst.server.is_within(b"/tmp", b"/tmp"));
    }

    #[test]
    fn handles_arbitrary_fids() {
        for ver in &[Plan9Type::Original, Plan9Type::Unix, Plan9Type::Linux] {
            let mut inst = instance(plan9_protocol(*ver));
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
                        fid(n),
                        format!("{:08x}", n).as_bytes(),
                        OpenMode::O_RDWR,
                        FileType::from_bits(0o660).unwrap(),
                        None,
                    )
                    .unwrap();
            }
            let seq = (0..=u32::MAX).map(minialzette);
            for n in seq.take(100) {
                // We run a stat to verify that the FID is still valid.
                let st = inst
                    .server
                    .getattr(&inst.next_meta(), fid(n), StatValidity::BASIC)
                    .unwrap();
                assert_eq!(st.length, 0);
                verify_file(&mut inst, fid(n), format!("dir/{:08x}", n).as_bytes());
                inst.server.clunk(&inst.next_meta(), fid(n)).unwrap();
            }
        }
    }

    fn read_directory_names(inst: &mut TestInstance, f: FID) -> HashSet<Vec<u8>> {
        let mut actual = HashSet::new();
        let mut offset = 0;
        loop {
            let entries = inst
                .server
                .readdir(
                    &inst.next_meta(),
                    f,
                    offset,
                    512,
                    Box::new(|_| 1),
                    Box::new(|e| 13 + 8 + 1 + 2 + e.name.len()),
                )
                .unwrap();
            if entries.is_empty() {
                break;
            }
            offset = entries[entries.len() - 1].offset;
            for entry in entries {
                actual.insert(entry.name);
            }
        }
        actual
    }

    #[test]
    fn readdir_remove() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
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
                    fid(n),
                    &path,
                    OpenMode::O_RDWR,
                    FileType::from_bits(0o660).unwrap(),
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
        inst.server
            .open(&inst.next_meta(), f, OpenMode::O_RDONLY)
            .unwrap();
        let actual = read_directory_names(&mut inst, f);
        assert_eq!(actual, set);
        let seq = (0..=u32::MAX).map(minialzette);
        for n in seq.take(100) {
            // We run a stat to verify that the FID is still valid.
            let st = inst
                .server
                .getattr(&inst.next_meta(), fid(n), StatValidity::BASIC)
                .unwrap();
            assert_eq!(st.length, 0);
            verify_file(&mut inst, fid(n), format!("dir/{:08x}", n).as_bytes());
            inst.server.remove(&inst.next_meta(), fid(n)).unwrap();
        }
        let actual = read_directory_names(&mut inst, f);
        let mut expected = HashSet::new();
        expected.insert(b"file".to_vec());
        assert_eq!(actual, expected);
    }

    // NetBSD fails this test with ENOSPC, suggesting that it might not support sparse files.
    #[cfg(not(target_os = "netbsd"))]
    #[test]
    fn truncate_64bit() {
        // This test assumes sparse files exist.
        const SIZE: u64 = 4_294_967_296;
        let mut inst = instance(plan9_protocol(Plan9Type::Original));
        create_fixtures(&mut inst);

        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        // Only the size is changed.
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
            .getattr(&inst.next_meta(), fid(1), StatValidity::BASIC)
            .unwrap();
        assert_eq!(st.length, 0x1_0000_0000);
        verify_file(&mut inst, fid(1), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn chmod_linux() {
        let mut inst = instance(plan9_protocol(Plan9Type::Unix));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"file"])
            .unwrap();
        inst.server
            .setattr(
                &inst.next_meta(),
                fid(1),
                Some((FileType::S_IFREG | FileType::from_bits(0o755).unwrap()).bits()),
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
            .getattr(&inst.next_meta(), fid(1), StatValidity::BASIC)
            .unwrap();
        assert_eq!(st.mode & 0o777, 0o755);
        verify_file(&mut inst, fid(1), b"dir/file");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
    }

    #[test]
    fn escape() {
        for ver in &[Plan9Type::Original, Plan9Type::Unix, Plan9Type::Linux] {
            let mut inst = instance(plan9_protocol(*ver));
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
        let mut inst = instance(plan9_protocol(Plan9Type::Unix));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .mkdir(
                &inst.next_meta(),
                fid(1),
                b"nested-dir",
                FileType::from_bits(0o770).unwrap(),
                None,
            )
            .unwrap();
        inst.server
            .resolve(&inst.next_meta(), fid(1), fid(1), &[b"nested-dir"])
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir/nested-dir"));
        inst.server
            .symlink(&inst.next_meta(), fid(1), b"symlink", b"../../..", None)
            .unwrap();
        inst.server
            .resolve(&inst.next_meta(), fid(1), fid(1), &[b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/nested-dir/symlink", b"../../..");
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"nested-dir"])
            .unwrap();
        inst.server
            .symlink(&inst.next_meta(), fid(2), b"symlink2", b"../..", None)
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
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(1),
                fid(1),
                b"foo",
                OpenMode::O_WRONLY,
                FileType::from_bits(0o600).unwrap(),
                None,
            )
            .unwrap();
        verify_file(&mut inst, fid(1), b"dir/foo");
    }

    #[test]
    fn remove_broken_symlink() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        inst.server
            .symlink(&inst.next_meta(), fid(1), b"symlink", b"/nonexistent", None)
            .unwrap();
        inst.server
            .walk(&inst.next_meta(), fid(1), fid(2), &[b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(2), b"dir/symlink", b"/nonexistent");
        inst.server.remove(&inst.next_meta(), fid(2)).unwrap();
    }

    #[test]
    fn open_remove_linux() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        // This mode is what the Linux kernel passes us as of 6.0, so let's make sure we handle it
        // gracefully.
        inst.server
            .open(
                &inst.next_meta(),
                fid(1),
                OpenMode::from_bits(0x18800).unwrap(),
            )
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(2), &[b"dir", b"file"])
            .unwrap();
        inst.server
            .open(
                &inst.next_meta(),
                fid(2),
                OpenMode::O_WRONLY | OpenMode::O_CREAT | OpenMode::O_NOCTTY | OpenMode::O_LARGEFILE,
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
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        // This mode is what the Linux kernel passes us as of 6.0, so let's make sure we handle it
        // gracefully.
        inst.server
            .open(
                &inst.next_meta(),
                fid(1),
                OpenMode::from_bits(0x18800).unwrap(),
            )
            .unwrap();
        verify_dir(&mut inst, fid(1), Some(b"dir"));
        inst.server
            .walk(&inst.next_meta(), fid(1), fid(2), &[])
            .unwrap();
        inst.server
            .open(
                &inst.next_meta(),
                fid(2),
                OpenMode::from_bits(0x18800).unwrap(),
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
    fn symlink_linux() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        create_fixtures(&mut inst);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir"])
            .unwrap();
        inst.server
            .symlink(&inst.next_meta(), fid(1), b"symlink", b"file", None)
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[b"dir", b"symlink"])
            .unwrap();
        verify_symlink(&mut inst, fid(1), b"dir/symlink", b"file");
        let dest = inst.server.readlink(&inst.next_meta(), fid(1)).unwrap();
        assert_eq!(dest, b"file");
        inst.server
            .open(
                &inst.next_meta(),
                fid(1),
                OpenMode::O_RDWR | OpenMode::O_TRUNC,
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
            .open(&inst.next_meta(), fid(1), OpenMode::O_RDWR)
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
            .getattr(&inst.next_meta(), fid(2), StatValidity::ALL)
            .unwrap();
        assert_eq!(st.length, message.len() as u64);
    }

    #[test]
    fn rename_linux() {
        for use_renameat in &[true, false] {
            let mut inst = instance(plan9_protocol(Plan9Type::Linux));
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
                .mkdir(
                    &inst.next_meta(),
                    fid(0),
                    b"other-dir",
                    FileType::from_bits(0o770).unwrap(),
                    None,
                )
                .unwrap();
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(3), &[b"other-dir"])
                .unwrap();
            verify_dir(&mut inst, fid(3), Some(b"other-dir"));
            inst.server
                .mkdir(
                    &inst.next_meta(),
                    fid(3),
                    b"nested-dir",
                    FileType::from_bits(0o770).unwrap(),
                    None,
                )
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
    fn files_and_directories_linux() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        attach(&mut inst);
        verify_dir(&mut inst, fid(0), None);
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(1), &[])
            .unwrap();
        inst.server
            .mkdir(
                &inst.next_meta(),
                fid(1),
                b"dir",
                FileType::from_bits(0o770).unwrap(),
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
                fid(2),
                b"file",
                OpenMode::O_RDWR,
                FileType::from_bits(0o660).unwrap(),
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
        inst.server
            .walk(&inst.next_meta(), fid(0), fid(3), &[b"dir"])
            .unwrap();
        let qid = inst
            .server
            .walk(&inst.next_meta(), fid(3), fid(4), &[b"file"])
            .unwrap();
        inst.server
            .link(&inst.next_meta(), fid(3), fid(2), b"other-file")
            .unwrap();
        let qid2 = inst
            .server
            .walk(&inst.next_meta(), fid(3), fid(5), &[b"other-file"])
            .unwrap();
        assert_eq!(qid, qid2);
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(3)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(4)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(5)).unwrap();
        verify_closed(&mut inst, fid(2));
        verify_closed(&mut inst, fid(3));
        verify_closed(&mut inst, fid(4));
        verify_closed(&mut inst, fid(5));
    }

    #[test]
    fn files_and_directories_resolve() {
        let mut inst = instance(plan9_protocol(Plan9Type::Linux));
        attach(&mut inst);
        verify_dir(&mut inst, fid(0), None);
        inst.server
            .resolve(&inst.next_meta(), fid(0), fid(1), &[])
            .unwrap();
        inst.server
            .mkdir(
                &inst.next_meta(),
                fid(1),
                b"dir",
                FileType::from_bits(0o770).unwrap(),
                None,
            )
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
        inst.server
            .resolve(&inst.next_meta(), fid(0), fid(2), &[b"dir"])
            .unwrap();
        verify_dir(&mut inst, fid(2), Some(b"dir"));
        inst.server
            .create(
                &inst.next_meta(),
                fid(2),
                fid(2),
                b"file",
                OpenMode::O_RDWR,
                FileType::from_bits(0o660).unwrap(),
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
        inst.server
            .resolve(&inst.next_meta(), fid(0), fid(3), &[b"dir"])
            .unwrap();
        let qid = inst
            .server
            .walk(&inst.next_meta(), fid(3), fid(4), &[b"file"])
            .unwrap();
        inst.server
            .link(&inst.next_meta(), fid(3), fid(2), b"other-file")
            .unwrap();
        let qid2 = inst
            .server
            .walk(&inst.next_meta(), fid(3), fid(5), &[b"other-file"])
            .unwrap();
        assert_eq!(qid, qid2);
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(3)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(4)).unwrap();
        inst.server.clunk(&inst.next_meta(), fid(5)).unwrap();
        verify_closed(&mut inst, fid(2));
        verify_closed(&mut inst, fid(3));
        verify_closed(&mut inst, fid(4));
        verify_closed(&mut inst, fid(5));
    }
}
