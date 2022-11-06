use super::{Backend, FileKind, QIDMapper, Result, ToIdentifier};
use crate::auth::Authenticator;
use crate::server::{
    DirEntry, FileType, IsFlush, LinuxFileType, LinuxOpenMode, LinuxStat, LinuxStatValidity, Lock,
    LockCommand, LockKind, LockStatus, Metadata, PlainStat, ProtocolVersion, SimpleOpenMode, Stat,
    Tag, UnixStat, FID, QID,
};
use flurry::HashMap;
use lawn_constants::logger::{AsLogStr, Logger};
use lawn_constants::Error;
use std::cmp;
use std::convert::TryInto;
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::fs::File;
use std::io;
use std::iter::Peekable;
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
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
        Ok(FileKind::from_metadata(&fs::metadata(&self.full_path)?))
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq)]
enum FIDKind<AH: ToIdentifier> {
    Open(OpenFileID),
    Closed(FileID),
    Auth(AH),
}

trait MaybeIDInfo {
    fn id_info(&self) -> Option<&dyn IDInfo>;
}

impl<AH: ToIdentifier> MaybeIDInfo for FIDKind<AH> {
    fn id_info(&self) -> Option<&dyn IDInfo> {
        match self {
            FIDKind::Open(f) => Some(f),
            FIDKind::Closed(f) => Some(f),
            FIDKind::Auth(_) => None,
        }
    }
}

impl<AH: ToIdentifier> FIDKind<AH> {
    fn file_kind(&self) -> Result<FileKind> {
        match self.id_info() {
            Some(idi) => idi.file_kind(),
            None => Ok(FileKind::Auth),
        }
    }
}

impl<AH: ToIdentifier> ToIdentifier for FIDKind<AH> {
    fn to_identifier(&self) -> Vec<u8> {
        match self {
            FIDKind::Open(f) => f.to_identifier(),
            FIDKind::Closed(f) => f.to_identifier(),
            FIDKind::Auth(a) => a.to_identifier(),
        }
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
            format!("b {} {}", unsafe { libc::major(meta.rdev()) }, unsafe {
                libc::minor(meta.rdev())
            })
            .into_bytes()
        } else if ft.is_char_device() {
            format!("c {} {}", unsafe { libc::major(meta.rdev()) }, unsafe {
                libc::minor(meta.rdev())
            })
            .into_bytes()
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

type CommitFn = Box<dyn FnMut() -> Result<()>>;

struct AtomicCommitter {
    ops: Vec<(CommitFn, Option<CommitFn>)>,
    completed: usize,
}

impl AtomicCommitter {
    fn new() -> Self {
        Self {
            ops: Vec::new(),
            completed: 0,
        }
    }

    fn add(&mut self, op: CommitFn, rollback: Option<CommitFn>) {
        self.ops.push((op, rollback));
    }

    fn commit(&mut self) -> Result<()> {
        for (i, (op, _)) in self.ops.iter_mut().enumerate() {
            (*op)()?;
            self.completed = i + 1;
        }
        Ok(())
    }

    fn rollback(&mut self) {
        // Already done successsfully.  No rollback to be done.
        if self.completed == self.ops.len() {
            return;
        }
        for (_, rollback) in self.ops[0..self.completed].iter_mut().rev() {
            if let Some(rollback) = rollback {
                let _ = (*rollback)();
            }
        }
    }
}

impl Drop for AtomicCommitter {
    fn drop(&mut self) {
        self.rollback()
    }
}

struct WalkState<'a> {
    root: &'a [u8],
    component: &'a [u8],
    kind: FileKind,
    full_path: PathBuf,
    next_full_path: PathBuf,
    dir: Option<Arc<File>>,
    file: Option<Arc<File>>,
    last: bool,
    dev: u64,
    ino: u64,
}

fn with_error<F: FnOnce() -> i32>(f: F) -> Result<i32> {
    let res = f();
    if res < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(res)
    }
}

#[allow(clippy::type_complexity)]
pub struct LibcBackend<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Clone + Send + Sync>
{
    max_size: u32,
    auth: A,
    fid: HashMap<FID, FIDKind<AH>>,
    dir_offsets:
        HashMap<FID, HashMap<(u64, ProtocolVersion), Option<Arc<Mutex<Peekable<fs::ReadDir>>>>>>,
    qidmapper: QIDMapper,
    root: RwLock<Option<Vec<u8>>>,
    logger: Arc<dyn Logger + Send + Sync>,
}

impl<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Clone + Send + Sync + 'static>
    LibcBackend<A, AH>
{
    pub fn new(
        logger: Arc<dyn Logger + Send + Sync>,
        auth: A,
        max_size: u32,
    ) -> LibcBackend<A, AH> {
        Self {
            max_size,
            auth,
            fid: HashMap::new(),
            dir_offsets: HashMap::new(),
            qidmapper: QIDMapper::new(),
            root: RwLock::new(None),
            logger,
        }
    }

    fn maybe_open_symlink(
        &self,
        full_path: &[u8],
        flags: i32,
        mode: u32,
    ) -> Result<(PathBuf, RawFd)> {
        let mut full_path = PathBuf::from(OsString::from_vec(full_path.into()));
        for _ in 0..40 {
            trace!(
                self.logger,
                "9P open: resolving path to {}",
                full_path.display()
            );
            let c = CString::new(full_path.as_os_str().as_bytes()).map_err(|_| Error::EINVAL)?;
            match with_error(|| unsafe { libc::open(c.as_ptr(), flags | libc::O_NOFOLLOW, mode) }) {
                Ok(fd) => return Ok((full_path, fd)),
                Err(Error::ELOOP) => {
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
    fn open_file(
        &self,
        full_path: &[u8],
        flags: i32,
        mode: u32,
        saved_path: Option<&[u8]>,
    ) -> Result<FIDKind<AH>> {
        trace!(self.logger, "9P open: opening {}", full_path.as_log_str());
        let (full_path, fd) = self.maybe_open_symlink(full_path, flags, mode)?;
        trace!(
            self.logger,
            "9P open: opened {}, fd {}",
            full_path.display(),
            fd
        );
        let f = unsafe { File::from_raw_fd(fd) };
        let metadata = f.metadata()?;
        let full_path = match saved_path {
            Some(p) => PathBuf::from(OsStr::from_bytes(p)),
            None => full_path,
        };
        Ok(FIDKind::Open(OpenFileID {
            dev: metadata.dev(),
            ino: metadata.ino(),
            file: Arc::new(f),
            full_path,
        }))
    }

    fn clone_with_mode(
        &self,
        f: &FIDKind<AH>,
        flags: i32,
        mode: Option<u32>,
    ) -> Result<FIDKind<AH>> {
        let idi = f.id_info().ok_or(Error::EOPNOTSUPP)?;
        let (file, full_path): (Option<RawFd>, _) =
            (idi.file().map(|f| f.as_raw_fd()), idi.full_path_bytes());
        let (fname, flags) = if let Some(file) = file {
            // The kernel will not like it if we try to open /dev/fd with O_DIRECTORY in this case
            // because it's not really a directory.
            (self.file_name(&file), flags & !libc::O_DIRECTORY)
        } else {
            (full_path.to_vec(), flags)
        };
        self.open_file(&fname, flags, mode.unwrap_or(0), Some(full_path))
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    fn file_name<F: AsRawFd>(&self, f: &F) -> Vec<u8> {
        let s = format!("/dev/fd/{}", f.as_raw_fd());
        s.into()
    }

    #[cfg(target_os = "linux")]
    fn fstatat_dev_ino<F: AsRawFd>(&self, f: &F, path: &[u8], follow: bool) -> Result<(u64, u64)> {
        let mut st = MaybeUninit::uninit();
        if path.is_empty() {
            with_error(|| unsafe { libc::fstat64(f.as_raw_fd(), st.as_mut_ptr()) })?;
        } else {
            let c = CString::new(path).map_err(|_| Error::EINVAL)?;
            let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
            with_error(|| unsafe {
                libc::fstatat64(f.as_raw_fd(), c.as_ptr(), st.as_mut_ptr(), flags)
            })?;
        }
        let data = unsafe { st.assume_init() };
        Ok((data.st_dev as u64, data.st_ino as u64))
    }

    #[cfg(not(target_os = "linux"))]
    fn fstatat_dev_ino<F: AsRawFd>(&self, f: &F, path: &[u8], follow: bool) -> Result<(u64, u64)> {
        let mut st = MaybeUninit::uninit();
        if path.is_empty() {
            with_error(|| unsafe { libc::fstat(f.as_raw_fd(), st.as_mut_ptr()) })?;
        } else {
            let c = CString::new(path).map_err(|_| Error::EINVAL)?;
            let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
            with_error(|| unsafe {
                libc::fstatat(f.as_raw_fd(), c.as_ptr(), st.as_mut_ptr(), flags)
            })?;
        }
        let data = unsafe { st.assume_init() };
        Ok((data.st_dev as u64, data.st_ino as u64))
    }

    #[cfg(target_os = "linux")]
    fn ftruncate<F: AsRawFd>(f: &F, size: u64) -> Result<()> {
        with_error(|| unsafe { libc::ftruncate64(f.as_raw_fd(), size as i64) })?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn ftruncate<F: AsRawFd>(f: &F, size: u64) -> Result<()> {
        with_error(|| unsafe { libc::ftruncate(f.as_raw_fd(), size as i64) })?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn truncate(full_path: &[u8], size: u64) -> Result<()> {
        let c = CString::new(full_path.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::truncate64(c.as_ptr(), size as i64) })?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn truncate(full_path: &[u8], size: u64) -> Result<()> {
        let c = CString::new(full_path.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::truncate(c.as_ptr(), size as i64) })?;
        Ok(())
    }

    fn lstat_dev_ino(&self, path: &[u8]) -> Result<(u64, u64)> {
        let os = Path::new(OsStr::from_bytes(path));
        let st = fs::symlink_metadata(os)?;
        Ok((st.dev() as u64, st.ino() as u64))
    }

    fn do_open(&self, fid: FID, flags: i32) -> Result<(QID, u32)> {
        let tg = self.fid.guard();
        match self.fid.get(&fid, &tg) {
            Some(e) => {
                let fk = self.clone_with_mode(e, flags, None)?;
                self.fid.remove(&fid, &tg);
                let ftk = fk.file_kind()?;
                let qid = self.qidmapper.qid_from_value(ftk, &fk);
                self.fid.insert(fid, fk, &tg);
                Ok((qid, 0))
            }
            None => Err(Error::EBADF),
        }
    }

    fn parse_major_minor(&self, s: &[u8]) -> Result<(u32, libc::dev_t)> {
        let mut items = s.split(|b| *b == b' ');
        let mmode = match items.next() {
            Some(b"b") => libc::S_IFBLK,
            Some(b"c") => libc::S_IFCHR,
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
        Ok((mmode as u32, libc::makedev(maj, min)))
    }

    fn system_time_to_timespec(&self, t: Option<SystemTime>, set: bool) -> libc::timespec {
        match (set, t) {
            (true, Some(t)) => match t.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(t) => libc::timespec {
                    tv_sec: t.as_secs() as libc::time_t,
                    tv_nsec: t.subsec_nanos() as libc::c_long,
                },
                Err(e) => libc::timespec {
                    tv_sec: -(e.duration().as_secs() as libc::time_t),
                    tv_nsec: e.duration().subsec_nanos() as libc::c_long,
                },
            },
            (true, None) => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_NOW,
            },
            (false, _) => libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
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

    fn qid_from_dev_ino(&self, kind: FileKind, dev: u64, ino: u64) -> QID {
        let mut buf = [0u8; 8 + 8];
        buf[0..8].copy_from_slice(&dev.to_le_bytes());
        buf[8..16].copy_from_slice(&ino.to_le_bytes());
        let v = buf.into();
        self.qidmapper.qid_from_vec(kind, v)
    }

    fn assert_valid_path_component(&self, path: &[u8], dotdot_ok: bool) -> Result<()> {
        if path.contains(&b'/') || (path == b".." && !dotdot_ok) {
            Err(Error::EINVAL)
        } else {
            Ok(())
        }
    }

    fn walk_one_non_parent(&self, dest: PathBuf, st: &'_ mut WalkState<'_>) -> Result<QID> {
        st.full_path = dest.clone();
        // If this is the last component, we don't need to try to open it since we're not walking a
        // directory.
        if st.last {
            let metadata = fs::symlink_metadata(&dest)?;
            let ft = if metadata.is_file() {
                FileKind::File
            } else if metadata.is_dir() {
                FileKind::Dir
            } else {
                FileKind::Special
            };
            st.kind = ft;
            st.next_full_path = st.full_path.clone();
            st.file = None;
            st.dev = metadata.dev();
            st.ino = metadata.ino();
            return Ok(self.qid_from_dev_ino(ft, metadata.dev(), metadata.ino()));
        }
        let c = CString::new(dest.as_os_str().as_bytes()).map_err(|_| Error::EINVAL)?;
        match with_error(|| unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW, 0) })
        {
            Ok(fd) => {
                // This is a file, directory, or something other than a symlink.
                let f = unsafe { File::from_raw_fd(fd) };
                let metadata = f.metadata()?;
                let ft = if metadata.is_file() {
                    FileKind::File
                } else if metadata.is_dir() {
                    FileKind::Dir
                } else {
                    FileKind::Special
                };
                st.kind = ft;
                st.next_full_path = st.full_path.clone();
                st.file = Some(Arc::new(f));
                st.dev = metadata.dev();
                st.ino = metadata.ino();
                Ok(self.qid_from_dev_ino(ft, metadata.dev(), metadata.ino()))
            }
            Err(Error::ELOOP) => {
                // This is a symlink.  We will read the value and replace our location
                // with a new path.  This may point outside of the root, but if that's the
                // case, we will verify that the path is valid in the next iteration, if any.
                let link_dest = dest.read_link()?;
                let metadata = dest.symlink_metadata()?;
                st.next_full_path.push(link_dest);
                st.next_full_path = st.full_path.canonicalize()?;
                st.file = None;
                st.kind = FileKind::Symlink;
                st.dev = metadata.dev();
                st.ino = metadata.ino();
                Ok(self.qid_from_dev_ino(FileKind::Symlink, metadata.dev(), metadata.ino()))
            }
            Err(e) => {
                // This is something we can't access, but we can finish here.
                Err(e)
            }
        }
    }

    fn walk_one(&self, st: &'_ mut WalkState<'_>) -> Result<QID> {
        self.assert_valid_path_component(st.component, true)?;
        if st.component == b".." {
            if st.full_path.as_os_str().as_bytes() == st.root {
                // This is defined to be a no-op.
                let (dev, ino) = self.lstat_dev_ino(st.full_path.as_os_str().as_bytes())?;
                let file = match &st.dir {
                    Some(d) => d.clone(),
                    None => {
                        let c = CString::new(st.root.to_vec()).map_err(|_| Error::EINVAL)?;
                        let fd = with_error(|| unsafe {
                            libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW, 0)
                        })?;
                        Arc::new(unsafe { File::from_raw_fd(fd) })
                    }
                };
                st.kind = FileKind::Dir;
                st.next_full_path = st.full_path.clone();
                st.file = Some(file);
                st.dev = dev;
                st.ino = ino;
                Ok(self.qid_from_dev_ino(FileKind::Dir, dev, ino))
            } else {
                st.full_path.pop();
                if !self.is_within(st.full_path.as_os_str().as_bytes(), st.root) {
                    return Err(Error::EACCES);
                }
                self.walk_one_non_parent(st.full_path.clone(), st)
            }
        } else {
            if !self.is_within(st.full_path.as_os_str().as_bytes(), st.root) {
                return Err(Error::EACCES);
            }
            let mut dest = st.full_path.clone();
            dest.push(OsStr::from_bytes(st.component));
            self.walk_one_non_parent(dest, st)
        }
    }

    fn readdir_entry_size(&self, entry: &DirEntry, ver: ProtocolVersion) -> usize {
        match ver {
            ProtocolVersion::Original => PlainStat::FIXED_SIZE + entry.name.len(),
            ProtocolVersion::Unix => {
                UnixStat::FIXED_SIZE
                    + entry.name.len()
                    + entry
                        .extension
                        .as_ref()
                        .map(|e| e.len())
                        .unwrap_or_default()
            }
            ProtocolVersion::Linux => entry.len(),
        }
    }

    fn fill_direntry(&self, path: &Path, name: &[u8], offset: u64) -> Result<DirEntry> {
        let metadata = fs::symlink_metadata(&path)?;
        let ft = metadata.file_type();
        let extension = if ft.is_symlink() {
            fs::read_link(&path)
                .map(|p| p.into_os_string().into_vec())
                .ok()
        } else if ft.is_char_device() {
            Some(
                format!("c {} {}", unsafe { libc::major(metadata.rdev()) }, unsafe {
                    libc::minor(metadata.rdev())
                })
                .into_bytes(),
            )
        } else if ft.is_block_device() {
            Some(
                format!("b {} {}", unsafe { libc::major(metadata.rdev()) }, unsafe {
                    libc::minor(metadata.rdev())
                })
                .into_bytes(),
            )
        } else {
            None
        };
        Ok(DirEntry {
            // TODO: map to proper type.
            qid: self.qid_from_dev_ino(FileKind::File, metadata.dev(), metadata.ino()),
            kind: 0,
            offset: offset + 1,
            name: name.to_vec(),
            extension,
            file_type: LinuxFileType::from_unix(metadata.mode()),
            size: metadata.size(),
            metadata,
        })
    }

    fn do_readdir(
        &self,
        fid: FID,
        offset: u64,
        kind: ProtocolVersion,
        count: u32,
    ) -> Result<Vec<DirEntry>> {
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
                    match map.remove(&(offset, kind), &idg) {
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
            let len = if let Some(de) = last_entry.take() {
                let _ = riter.next();
                let len = self.readdir_entry_size(&de, kind);
                trace!(
                    self.logger,
                    "9P readdir; existing entry {}; {} bytes for {:?}",
                    (&*de.name).as_log_str(),
                    len,
                    kind
                );
                res.push(de);
                len
            } else {
                let entry = riter.next();
                let entry = match entry {
                    Some(entry) => entry,
                    None => break,
                };
                let entry = entry?;
                trace!(
                    self.logger,
                    "9P readdir; reading entry {}",
                    entry.file_name().as_bytes().as_log_str()
                );
                let mut path = idi.full_path().to_owned();
                path.push(entry.file_name());
                let de = self.fill_direntry(&path, entry.file_name().as_bytes(), offset)?;
                let len = self.readdir_entry_size(&de, kind);
                trace!(
                    self.logger,
                    "9P readdir; entry: {} bytes for {:?}",
                    len,
                    kind
                );
                res.push(de);
                len
            };
            offset += match kind {
                ProtocolVersion::Linux => 1,
                _ => len as u64,
            };
            msg_size += len;
            trace!(
                self.logger,
                "9P readdir; offset is now {}; msg size is {}",
                offset,
                msg_size
            );
            if let Some(Ok(entry)) = riter.peek() {
                trace!(
                    self.logger,
                    "9P readdir; peeking entry {}",
                    entry.file_name().as_bytes().as_log_str()
                );
                let mut path = idi.full_path().to_owned();
                path.push(entry.file_name());
                let de = self.fill_direntry(&path, entry.file_name().as_bytes(), offset)?;
                let len = self.readdir_entry_size(&de, kind);
                trace!(
                    self.logger,
                    "9P readdir; entry: {} bytes for {:?}",
                    len,
                    kind
                );
                last_entry = Some(de);
                if msg_size + len > max_size {
                    trace!(
                        self.logger,
                        "9P readdir; entry too large ({} > {})",
                        msg_size + len,
                        max_size
                    );
                    let offmap = match self.dir_offsets.try_insert(fid, HashMap::default(), &dg) {
                        Ok(map) => map,
                        Err(e) => e.current,
                    };
                    let og = offmap.guard();
                    offmap.insert((offset, kind), Some(iter.clone()), &og);
                    return Ok(res);
                }
            }
        }
        let offmap = match self.dir_offsets.try_insert(fid, HashMap::default(), &dg) {
            Ok(map) => map,
            Err(e) => e.current,
        };
        let og = offmap.guard();
        offmap.insert((offset, kind), None, &og);
        Ok(res)
    }
}

impl<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Clone + Send + Sync + 'static> Backend
    for LibcBackend<A, AH>
{
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
        _meta: &Metadata,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let handle = self.auth.create(uname, aname, nuname);
        let handle = FIDKind::Auth(handle);
        let qid = self.qidmapper.qid_from_value(FileKind::Auth, &handle);
        {
            let g = self.fid.guard();
            if self.fid.try_insert(afid, handle, &g).is_err() {
                return Err(Error::EINVAL);
            };
        }
        Ok(qid)
    }

    fn attach(
        &self,
        _meta: &Metadata,
        fid: FID,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID> {
        let file = {
            let handle;
            let g;
            trace!(self.logger, "9P attach: fid {} afid {}", fid, afid);
            let info = match afid {
                FID([0xff, 0xff, 0xff, 0xff]) => {
                    trace!(self.logger, "9P attach: using anonymous auth");
                    handle = self.auth.create(uname, aname, nuname);
                    match self.auth.info(&handle) {
                        Some(info) => {
                            trace!(self.logger, "9P attach: anonymous auth OK");
                            info
                        }
                        None => {
                            trace!(self.logger, "9P attach: anonymous auth failed");
                            return Err(Error::EACCES);
                        }
                    }
                }
                _ => {
                    trace!(self.logger, "9P attach: using non-anonymous auth");
                    g = self.fid.guard();
                    let auth = match self.fid.get(&afid, &g) {
                        Some(FIDKind::Auth(a)) => a,
                        _ => return Err(Error::EBADF),
                    };
                    match self.auth.info(auth) {
                        Some(info) => info,
                        None => return Err(Error::EACCES),
                    }
                }
            };
            // TODO: implement Display for byte strings.
            trace!(
                self.logger,
                "9P attach: uname {} user {} aname {} dir {} nuname {:?} id {:?}",
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
            let file = self.open_file(location, libc::O_RDONLY, 0, None)?;
            trace!(
                self.logger,
                "9P attach: mounting location \"{}\" as root: fid {}",
                location.as_log_str(),
                fid
            );
            *self.root.write().unwrap() = Some(info.location().to_vec());
            file
        };
        trace!(self.logger, "9P attach: mapping fid");
        let qid = self.qidmapper.qid_from_value(file.file_kind()?, &file);
        let g = self.fid.guard();
        match self.fid.try_insert(fid, file, &g) {
            Ok(_) => {
                trace!(self.logger, "9P attach: mapping fid OK");
                Ok(qid)
            }
            Err(_) => Err(Error::EBADF),
        }
    }

    fn clunk(&self, _meta: &Metadata, fid: FID) -> Result<()> {
        trace!(self.logger, "9P clunk: fid {}", fid);
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

    fn open(&self, _meta: &Metadata, fid: FID, mode: SimpleOpenMode) -> Result<(QID, u32)> {
        trace!(self.logger, "9P open: fid {} mode {:?}", fid, mode);
        let mode = match mode.to_unix() {
            Some(mode) => mode,
            None => return Err(Error::EINVAL),
        };
        self.do_open(fid, mode)
    }

    fn lopen(&self, _meta: &Metadata, fid: FID, mode: LinuxOpenMode) -> Result<(QID, u32)> {
        trace!(self.logger, "9P lopen: fid {} mode {:?}", fid, mode);
        let mode = match mode.to_unix() {
            Some(mode) => mode,
            None => return Err(Error::EINVAL),
        };
        trace!(self.logger, "9P lopen: opening file");
        self.do_open(fid, mode)
    }
    fn create(
        &self,
        _meta: &Metadata,
        fid: FID,
        name: &[u8],
        perm: FileType,
        omode: SimpleOpenMode,
        extension: Option<&[u8]>,
    ) -> Result<(QID, u32)> {
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
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let dir_path = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi.full_path(),
            _ => return Err(Error::ENOTDIR),
        };
        let mut full_path = dir_path.to_owned();
        full_path.push(OsStr::from_bytes(name));
        let cpath =
            CString::new(Vec::from(full_path.as_os_str().as_bytes())).map_err(|_| Error::EINVAL)?;
        let (mmode, mdev) = match (
            perm & !(FileType::DMACCMODE | FileType::DMSETUID | FileType::DMSETGID),
            extension,
        ) {
            (FileType::DMDIR, None) => {
                trace!(self.logger, "9P create: directory: {}", full_path.display());
                with_error(|| unsafe { libc::mkdir(cpath.as_ptr(), mode) })?;
                trace!(
                    self.logger,
                    "9P create: directory creation OK, statting directory"
                );
                let md = fs::symlink_metadata(&full_path)?;
                let file = FIDKind::Closed(FileID {
                    dev: md.dev(),
                    ino: md.ino(),
                    full_path,
                });
                let qid = self
                    .qidmapper
                    .qid_from_value(FileKind::from_metadata(&md), &file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (FileType::DMSYMLINK, Some(dest)) => {
                trace!(
                    self.logger,
                    "9P create: symlink: {} {}",
                    full_path.display(),
                    dest.as_log_str()
                );
                std::os::unix::fs::symlink(OsStr::from_bytes(dest), &full_path)?;
                let md = fs::symlink_metadata(&full_path)?;
                let file = FIDKind::Closed(FileID {
                    dev: md.dev(),
                    ino: md.ino(),
                    full_path,
                });
                let qid = self
                    .qidmapper
                    .qid_from_value(FileKind::from_metadata(&md), &file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (x, None) if x == FileType::empty() => {
                trace!(self.logger, "9P create: file: {}", full_path.display());
                let omode = omode.to_unix().ok_or(Error::EINVAL)? | libc::O_CREAT | libc::O_EXCL;
                let file = self.open_file(full_path.as_os_str().as_bytes(), omode, mode, None)?;
                let md = fs::symlink_metadata(&full_path)?;
                let qid = self
                    .qidmapper
                    .qid_from_value(FileKind::from_metadata(&md), &file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (FileType::DMDEVICE, Some(kind)) => self.parse_major_minor(kind)?,
            (FileType::DMSOCKET, None) => (libc::S_IFSOCK, 0),
            (FileType::DMNAMEDPIPE, None) => (libc::S_IFIFO, 0),
            _ => return Err(Error::EINVAL),
        };
        trace!(self.logger, "9P create: mknod: {}", full_path.display());
        with_error(|| unsafe { libc::mknod(cpath.as_ptr(), mmode, mdev) })?;
        let md = fs::symlink_metadata(&full_path)?;
        let file = FIDKind::Closed(FileID {
            dev: md.dev(),
            ino: md.ino(),
            full_path,
        });
        let qid = self
            .qidmapper
            .qid_from_value(FileKind::from_metadata(&md), &file);
        self.fid.insert(fid, file, &g);
        Ok((qid, 0))
    }
    fn lcreate(
        &self,
        _meta: &Metadata,
        fid: FID,
        name: &[u8],
        _flags: u32,
        mode: u32,
        _gid: u32,
    ) -> Result<(QID, u32)> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let dir_path = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi.full_path(),
            _ => return Err(Error::ENOTDIR),
        };
        let mut full_path = dir_path.to_owned();
        full_path.push(OsStr::from_bytes(name));
        let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_EXCL;
        let file = self.open_file(full_path.as_os_str().as_bytes(), flags, mode, None)?;
        let md = file.id_info().unwrap().file().unwrap().metadata()?;
        let qid = self
            .qidmapper
            .qid_from_value(FileKind::from_metadata(&md), &file);
        self.fid.insert(fid, file, &g);
        Ok((qid, 0))
    }
    fn read(&self, meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32> {
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi,
            _ => return Err(Error::EBADF),
        };
        match (idi.file_kind()?, idi.file()) {
            (FileKind::File, Some(fh)) => match fh.read_at(data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            (FileKind::Dir, Some(_)) => {
                let entries = self.do_readdir(fid, offset, meta.protocol, data.len() as u32)?;
                let mut size = 0;
                let path = idi.full_path();
                for entry in entries {
                    let mut path: PathBuf = path.into();
                    path.push(OsStr::from_bytes(&entry.name));
                    let fsmeta = &entry.metadata;
                    match meta.protocol {
                        ProtocolVersion::Original => {
                            let mut st = PlainStat::from_metadata(fsmeta).ok_or(Error::EIO)?;
                            st.qid = entry.qid;
                            st.qid.0[0] = (st.mode >> 24) as u8;
                            st.size += entry.name.len() as u16;
                            st.name = entry.name;
                            let st = st.to_bytes().ok_or(Error::EIO)?;
                            data[size..size + st.len()].copy_from_slice(&st);
                            size += st.len();
                        }
                        ProtocolVersion::Unix | ProtocolVersion::Linux => {
                            let mut st = UnixStat::from_metadata(fsmeta).ok_or(Error::EIO)?;
                            st.qid = entry.qid;
                            st.qid.0[0] = (st.mode >> 24) as u8;
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
            (FileKind::File, None) | (FileKind::Dir, None) => Err(Error::EBADF),
            _ => Err(Error::EINVAL),
        }
    }
    fn write(&self, _meta: &Metadata, fid: FID, offset: u64, data: &[u8]) -> Result<u32> {
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
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
            Some(Some(idi)) => idi,
            _ => return Err(Error::EBADF),
        };
        match (idi.file_kind()?, idi.file()) {
            (FileKind::File, Some(fh)) => match fh.write_at(data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            (kind, Some(_)) => {
                trace!(self.logger, "9P write: invalid type {:?}", kind);
                Err(Error::EBADF)
            }
            (_, None) => {
                trace!(self.logger, "9P write: no such descriptor");
                Err(Error::EBADF)
            }
        }
    }
    fn remove(&self, meta: &Metadata, fid: FID) -> Result<()> {
        trace!(self.logger, "9P remove: fid {}", fid);
        let g = self.fid.guard();
        match self.fid.get(&fid, &g) {
            Some(fk) => {
                let _ = self.clunk(meta, fid);
                let full_path = match fk.id_info().map(|idi| idi.full_path()) {
                    Some(p) => p,
                    _ => return Err(Error::EOPNOTSUPP),
                };
                let ftk = fk.file_kind()?;
                trace!(
                    self.logger,
                    "9P remove: kind {:?} path {:?}",
                    ftk,
                    full_path,
                );
                if ftk == FileKind::Dir {
                    fs::remove_dir(&full_path)?
                } else {
                    fs::remove_file(&full_path)?
                }
                Ok(())
            }
            None => Err(Error::EBADF),
        }
    }
    fn fsync(&self, _meta: &Metadata, fid: FID) {
        let g = self.fid.guard();
        if let Some(FIDKind::Open(fh)) = self.fid.get(&fid, &g) {
            let _ = fh.file.sync_all();
        }
    }
    fn stat(&self, meta: &Metadata, fid: FID) -> Result<Box<dyn Stat>> {
        trace!(self.logger, "9P stat: fid {}", fid);
        match meta.protocol {
            ProtocolVersion::Original => {
                let g = self.fid.guard();
                let desc = match self.fid.get(&fid, &g) {
                    Some(desc) => desc,
                    None => return Err(Error::EBADF),
                };
                trace!(self.logger, "9P stat: found fid {}", fid);
                let full_path = match desc {
                    FIDKind::Open(fh) => fh.full_path(),
                    FIDKind::Closed(fh) => fh.full_path(),
                    FIDKind::Auth(_) => {
                        let qid = self.qidmapper.qid_from_value(FileKind::Auth, desc);
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
                };
                let fsmeta = fs::symlink_metadata(&full_path)?;
                let mut pst = PlainStat::from_metadata(&fsmeta).ok_or(Error::ENOMEM)?;
                pst.qid = self.qid_from_dev_ino(
                    FileKind::from_metadata(&fsmeta),
                    fsmeta.dev(),
                    fsmeta.ino(),
                );
                let root = self.root.read().unwrap();
                pst.name = if let Some(ref p) = *root {
                    if p.as_slice() == full_path.as_os_str().as_bytes() {
                        vec![b'/']
                    } else {
                        full_path.file_name().unwrap().as_bytes().to_vec()
                    }
                } else {
                    full_path.file_name().unwrap().as_bytes().to_vec()
                };
                pst.size += pst.name.len() as u16;
                trace!(
                    self.logger,
                    "9P stat: created plain stat of {} bytes",
                    pst.size + 2
                );
                Ok(Box::new(pst))
            }
            ProtocolVersion::Unix => {
                let g = self.fid.guard();
                let desc = match self.fid.get(&fid, &g) {
                    Some(desc) => desc,
                    None => return Err(Error::EBADF),
                };
                trace!(self.logger, "9P stat: found fid {}", fid);
                let full_path = match desc {
                    FIDKind::Open(fh) => fh.full_path(),
                    FIDKind::Closed(fh) => fh.full_path(),
                    FIDKind::Auth(_) => {
                        let qid = self.qidmapper.qid_from_value(FileKind::Auth, desc);
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
                };
                let fsmeta = fs::symlink_metadata(&full_path)?;
                let ftk = FileKind::from_metadata(&fsmeta);
                let mut ust = UnixStat::from_metadata(&fsmeta).ok_or(Error::ENOMEM)?;
                ust.qid = self.qid_from_dev_ino(ftk, fsmeta.dev(), fsmeta.ino());
                let root = self.root.read().unwrap();
                ust.name = if let Some(ref p) = *root {
                    if p.as_slice() == full_path.as_os_str().as_bytes() {
                        vec![b'/']
                    } else {
                        full_path.file_name().unwrap().as_bytes().to_vec()
                    }
                } else {
                    full_path.file_name().unwrap().as_bytes().to_vec()
                };
                ust.size += ust.name.len() as u16;
                if ftk == FileKind::Symlink {
                    ust.extension = match fs::read_link(full_path) {
                        Ok(p) => p.into_os_string().into_vec(),
                        Err(_) => vec![],
                    };
                    ust.size += ust.extension.len() as u16;
                }
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
        match meta.protocol {
            ProtocolVersion::Original | ProtocolVersion::Unix => {
                let g = self.fid.guard();
                let idi = match self.fid.get(&fid, &g).map(|f| f.id_info()) {
                    Some(Some(idi)) => idi,
                    _ => return Err(Error::EBADF),
                };
                let full_path = idi.full_path().to_owned();
                let metadata = match idi.file() {
                    Some(ref f) => f.metadata()?,
                    None => fs::symlink_metadata(&full_path)?,
                };
                let file = idi.file();
                std::mem::drop(g);
                let is_symlink = FileKind::from_metadata(&metadata) == FileKind::Symlink;
                if !stat.kind().is_flush()
                    || !stat.dev().unwrap_or(u32::MAX).is_flush()
                    || (!is_symlink && stat.extension().is_some())
                {
                    return Err(Error::EINVAL);
                }
                let mut ac = AtomicCommitter::new();
                let mut dest_full_path: PathBuf = full_path.clone();
                if !stat.name().is_empty() {
                    dest_full_path = dest_full_path.parent().unwrap().into();
                    dest_full_path.push(OsStr::from_bytes(stat.name()));
                    let fp1 = full_path.clone();
                    let fp2 = full_path.clone();
                    let dfp1 = dest_full_path.clone();
                    let dfp2 = dest_full_path.clone();
                    // We don't yet support changing the name of a file in this way.
                    ac.add(
                        Box::new(move || fs::rename(&fp1, &dfp1).map_err(|e| e.into())),
                        Some(Box::new(move || {
                            fs::rename(&dfp2, &fp2).map_err(|e| e.into())
                        })),
                    )
                }
                if is_symlink && stat.extension().is_some() {
                    // We don't yet support changing the destination of a symlink.
                    return Err(Error::EOPNOTSUPP);
                }
                if let Some(stgid) = stat.ngid() {
                    let oldgid = metadata.gid();
                    if !stgid.is_flush() && oldgid != stgid {
                        let file = file.clone();
                        let rfile = file.clone();
                        let c = CString::new(Vec::from(full_path.as_os_str().as_bytes()))
                            .map_err(|_| Error::EINVAL)?;
                        let c2 = c.clone();
                        ac.add(
                            Box::new(move || {
                                match file {
                                    Some(ref f) => with_error(|| unsafe {
                                        libc::fchown(
                                            f.as_raw_fd(),
                                            -1i32 as libc::uid_t,
                                            stgid as libc::gid_t,
                                        )
                                    })?,
                                    None => with_error(|| unsafe {
                                        libc::chown(
                                            c.as_ptr(),
                                            -1i32 as libc::uid_t,
                                            stgid as libc::gid_t,
                                        )
                                    })?,
                                };
                                Ok(())
                            }),
                            Some(Box::new(move || {
                                match rfile {
                                    Some(ref f) => with_error(|| unsafe {
                                        libc::fchown(
                                            f.as_raw_fd(),
                                            -1i32 as libc::uid_t,
                                            oldgid as libc::gid_t,
                                        )
                                    })?,
                                    None => with_error(|| unsafe {
                                        libc::chown(
                                            c2.as_ptr(),
                                            -1i32 as libc::uid_t,
                                            oldgid as libc::gid_t,
                                        )
                                    })?,
                                };
                                Ok(())
                            })),
                        );
                    }
                }
                if let Some(stmode) = stat.mode() {
                    let oldmode = metadata.mode() & 0o7777;
                    let mut mode = stmode.bits() & 0o777;
                    if stmode.contains(FileType::DMSETUID) {
                        mode |= 0o4000;
                    }
                    if stmode.contains(FileType::DMSETGID) {
                        mode |= 0o2000;
                    }
                    if oldmode & 0o6777 != mode {
                        let file = file.clone();
                        let rfile = file.clone();
                        let c = CString::new(Vec::from(full_path.as_os_str().as_bytes()))
                            .map_err(|_| Error::EINVAL)?;
                        let c2 = c.clone();
                        ac.add(
                            Box::new(move || {
                                match file {
                                    Some(ref f) => {
                                        with_error(|| unsafe { libc::fchmod(f.as_raw_fd(), mode) })?
                                    }
                                    None => {
                                        with_error(|| unsafe { libc::chmod(c.as_ptr(), mode) })?
                                    }
                                };
                                Ok(())
                            }),
                            Some(Box::new(move || {
                                match rfile {
                                    Some(ref f) => with_error(|| unsafe {
                                        libc::fchmod(f.as_raw_fd(), oldmode)
                                    })?,
                                    None => {
                                        with_error(|| unsafe { libc::chmod(c2.as_ptr(), oldmode) })?
                                    }
                                };
                                Ok(())
                            })),
                        );
                    }
                }
                if !stat.length().is_flush() {
                    let len = stat.length();
                    if len != metadata.len() {
                        let full_path = full_path.clone();
                        ac.add(
                            Box::new(move || {
                                match file {
                                    Some(ref f) => Self::ftruncate(&f.as_raw_fd(), len)?,
                                    None => Self::truncate(full_path.as_os_str().as_bytes(), len)?,
                                };
                                Ok(())
                            }),
                            None,
                        );
                    }
                }
                match ac.commit() {
                    Ok(()) => {
                        if dest_full_path != full_path {
                            let g = self.fid.guard();
                            match self.fid.get(&fid, &g) {
                                Some(FIDKind::Open(f)) => {
                                    self.fid.insert(
                                        fid,
                                        FIDKind::Open(OpenFileID {
                                            dev: f.dev,
                                            ino: f.ino,
                                            file: f.file.clone(),
                                            full_path: dest_full_path,
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
                                            full_path: dest_full_path,
                                        }),
                                        &g,
                                    );
                                }
                                Some(FIDKind::Auth(s)) => {
                                    self.fid.insert(fid, FIDKind::Auth(s.clone()), &g);
                                }
                                None => (),
                            }
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            _ => Err(Error::EOPNOTSUPP),
        }
    }
    fn walk(&self, _meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<Vec<QID>> {
        trace!(
            self.logger,
            "9P walk: fid {} newfid {} components {}",
            fid,
            newfid,
            name.len()
        );
        let g = self.root.read().unwrap();
        let root = match &*g {
            Some(root) => root,
            None => return Err(Error::EACCES),
        };
        trace!(self.logger, "9P walk: found root");
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
                "9P walk: verifying full path for fd {} path {}",
                file.as_raw_fd(),
                full_path.display(),
            );
            let fst = self.fstatat_dev_ino(&file.as_raw_fd(), b"", false)?;
            let lst = self.lstat_dev_ino(full_path.as_os_str().as_bytes())?;
            trace!(
                self.logger,
                "9P walk: verifying full path: fstatat {}/{} lstat {}/{}",
                fst.0,
                fst.1,
                lst.0,
                lst.1
            );
            if fst != lst {
                return Err(Error::EIO);
            }
        }
        trace!(self.logger, "9P walk: full path verified");
        let buf = [0u8; 0];
        let mut st = WalkState {
            root,
            component: &buf,
            dir: None,
            file,
            kind: FileKind::File,
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
                "9P walk: walking component \"{}\"",
                component.as_log_str()
            );
            match (i, self.walk_one(&mut st)) {
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
            "9P walk: walk completed, {} components",
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
        _gid: u32,
    ) -> Result<QID> {
        self.assert_valid_path_component(name, false)?;
        let rg = self.root.read().unwrap();
        let root = match *rg {
            Some(ref r) => r,
            None => return Err(Error::EINVAL),
        };
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let mut full_path = idi.full_path().to_owned();
        full_path.push(OsStr::from_bytes(name));
        let target = if target.starts_with(b"/") {
            let mut full_path = root.clone();
            full_path.extend(target);
            full_path
        } else {
            target.to_vec()
        };
        let ctarget = CString::new(target).map_err(|_| Error::EINVAL)?;
        let cname =
            CString::new(full_path.as_os_str().as_bytes().to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::symlink(ctarget.as_ptr(), cname.as_ptr()) })?;
        let meta = fs::symlink_metadata(&full_path)?;
        Ok(self.qid_from_dev_ino(FileKind::Symlink, meta.dev(), meta.ino()))
    }
    fn mknod(
        &self,
        _meta: &Metadata,
        _fid: FID,
        _name: &[u8],
        _mode: u32,
        _major: u32,
        _minor: u32,
        _gid: u32,
    ) -> Result<QID> {
        // TODO: create devices and FIFOs.
        Err(Error::EOPNOTSUPP)
    }
    fn rename(&self, _meta: &Metadata, fid: FID, dfid: FID, newname: &[u8]) -> Result<()> {
        self.assert_valid_path_component(newname, false)?;
        let g = self.fid.guard();
        trace!(self.logger, "9P rename: verifying IDs");
        let oldidi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "9P rename: verified fid {}", fid);
        let newidi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "9P rename: verified fid {}", dfid);
        let oldname = oldidi.full_path();
        trace!(self.logger, "9P rename: verified path info");
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
    fn getattr(&self, _meta: &Metadata, fid: FID, mask: LinuxStatValidity) -> Result<LinuxStat> {
        trace!(self.logger, "9P getattr: fid {} mask {:?}", fid, mask);
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let full_path = idi.full_path();
        let meta = fs::symlink_metadata(full_path)?;
        let ft = FileKind::from_metadata(&meta);
        let mut st = LinuxStat::from_metadata(&meta).ok_or(Error::EOVERFLOW)?;
        st.qid = self.qid_from_dev_ino(ft, meta.dev(), meta.ino());
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
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => {
                trace!(self.logger, "9P setattr: kind {:?}", idi.file_kind());
                idi.id_info().ok_or(Error::EOPNOTSUPP)?
            }
            None => return Err(Error::EBADF),
        };
        trace!(self.logger, "9P setattr: verified fid");
        let file = idi.file();
        let full_path = idi.full_path();
        let cpath =
            CString::new(full_path.as_os_str().as_bytes().to_vec()).map_err(|_| Error::EINVAL)?;
        if let Some(mode) = mode {
            with_error(|| unsafe { libc::chmod(cpath.as_ptr(), mode & 0o7777) })?;
        }
        if uid.is_some() || gid.is_some() {
            with_error(|| unsafe {
                libc::chown(
                    cpath.as_ptr(),
                    uid.unwrap_or(-1i32 as libc::uid_t),
                    gid.unwrap_or(-1i32 as libc::gid_t),
                )
            })?;
        }
        if let Some(size) = size {
            match file {
                Some(f) => Self::ftruncate(&f.as_raw_fd(), size)?,
                None => Self::truncate(full_path.as_os_str().as_bytes(), size)?,
            };
        }
        if atime.is_some() || mtime.is_some() {
            let times = [
                self.system_time_to_timespec(atime, set_atime),
                self.system_time_to_timespec(mtime, set_mtime),
            ];
            with_error(|| unsafe { libc::utimensat(-1, cpath.as_ptr(), times.as_ptr(), 0) })?;
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
    fn readdir(&self, meta: &Metadata, fid: FID, offset: u64, count: u32) -> Result<Vec<DirEntry>> {
        self.do_readdir(fid, offset, meta.protocol, count)
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
        let oldpath = CString::new(idi.full_path().as_os_str().as_bytes().to_vec())
            .map_err(|_| Error::EINVAL)?;
        let newpath = CString::new(dpath.into_os_string().into_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::link(oldpath.as_ptr(), newpath.as_ptr()) })?;
        Ok(())
    }
    fn mkdir(&self, _meta: &Metadata, dfid: FID, name: &[u8], mode: u32, _gid: u32) -> Result<QID> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let didi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let mut full_path = didi.full_path().to_owned();
        full_path.push(OsStr::from_bytes(name));
        let mode = mode & 0o7777;
        let cname =
            CString::new(Vec::from(full_path.as_os_str().as_bytes())).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::mkdir(cname.as_ptr(), mode) })?;
        let meta = fs::symlink_metadata(&full_path)?;
        Ok(self.qid_from_dev_ino(FileKind::Dir, meta.dev(), meta.ino()))
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
            "9P renameat: {}/{} -> {}/{}",
            olddirfid,
            oldname.as_log_str(),
            newdirfid,
            newname.as_log_str()
        );
        self.assert_valid_path_component(oldname, false)?;
        self.assert_valid_path_component(newname, false)?;
        trace!(self.logger, "9P renameat: verifying IDs");
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
            "9P renameat: verified fid {}: {}; fid {}: {}",
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

#[cfg(test)]
mod tests {
    use super::{IDInfo, LibcBackend, MaybeIDInfo};
    use crate::auth::{AuthenticationInfo, Authenticator};
    use crate::backend::{Backend, FIDKind, ToIdentifier};
    use crate::server::{
        FileType, LinuxFileType, LinuxOpenMode, LinuxStatValidity, Metadata, PlainStat,
        ProtocolVersion, SimpleOpenMode, Tag, UnixStat, FID,
    };
    use lawn_constants::logger::{LogFormat, LogLevel};
    use lawn_constants::Error;
    use std::collections::HashSet;
    use std::convert::TryInto;
    use std::ffi::OsStr;
    use std::fs;
    use std::fs::File;
    use std::fs::FileType as StdFileType;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::io::AsRawFd;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::Mutex;
    use tempfile::TempDir;

    #[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
    pub struct AutherHandle {
        user: Vec<u8>,
        dir: Vec<u8>,
        id: Option<u32>,
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
        type SessionHandle = AutherHandle;

        fn create(&self, uname: &[u8], aname: &[u8], nuname: Option<u32>) -> Self::SessionHandle {
            Self::SessionHandle {
                user: self.user.clone(),
                dir: self.dir.clone(),
                id: nuname,
            }
        }

        fn read(&self, _handle: &mut Self::SessionHandle, _data: &mut [u8]) -> Result<u32, Error> {
            Err(Error::EOPNOTSUPP)
        }

        fn write(&self, _handle: &mut Self::SessionHandle, _data: &[u8]) -> Result<u32, Error> {
            Err(Error::EOPNOTSUPP)
        }

        fn info<'a>(&self, handle: &'a Self::SessionHandle) -> Option<AuthenticationInfo<'a>> {
            Some(AuthenticationInfo::new(
                handle.id,
                &*handle.user,
                &*handle.dir,
                &*handle.dir,
            ))
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
        fn fatal(&self, msg: &str) {}
        fn error(&self, msg: &str) {}
        fn message(&self, msg: &str) {}
        fn info(&self, msg: &str) {}
        fn debug(&self, msg: &str) {}
        fn trace(&self, msg: &str) {
            eprintln!("{}", msg);
        }
    }

    type Server = LibcBackend<Auther, AutherHandle>;

    struct TestInstance {
        dir: TempDir,
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
        TestInstance {
            version,
            server: Server::new(
                Arc::new(Logger {}),
                Auther {
                    user: "foo".into(),
                    dir: dir.path().as_os_str().as_bytes().into(),
                },
                1024 * 1024,
            ),
            dir,
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

    fn verify_file_is_path<F: FnOnce(&StdFileType) -> bool>(
        inst: &TestInstance,
        file: Option<Arc<File>>,
        path: &Path,
        f: F,
    ) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        assert!(f(&meta.file_type()), "file is of correct type");
        if let Some(file) = file {
            let (dev, ino) = inst
                .server
                .fstatat_dev_ino(&file.as_raw_fd(), b"", false)
                .unwrap();
            assert_eq!((dev, ino), (meta.dev(), meta.ino()), "same file");
        }
    }

    fn verify_dir(inst: &mut TestInstance, fid: FID, path: Option<&[u8]>) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(idi) = entry.and_then(|e| e.id_info()) {
            let mut full_path = inst.dir.path().to_owned();
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
                        assert_eq!(full_path, inst.dir.path(), "path is root");
                    } else {
                        assert_eq!(idi.full_path(), full_path, "path is correct");
                    }
                }
                None => assert_eq!(full_path, inst.dir.path(), "path is root"),
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
            let mut full_path = inst.dir.path().to_owned();
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
            let mut full_path = inst.dir.path().to_owned();
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
            .create(
                &inst.next_meta(),
                fid(1),
                b"dir",
                FileType::DMDIR | FileType::from_bits(0o770).unwrap(),
                SimpleOpenMode::O_READ,
                None,
            )
            .unwrap();
        inst.server.clunk(&inst.next_meta(), fid(1));
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
        inst.server.clunk(&inst.next_meta(), fid(2));
        verify_closed(inst, fid(2));
    }

    #[test]
    fn is_within() {
        let mut inst = instance(ProtocolVersion::Original);
        assert!(inst.server.is_within(b"/tmp/foo", b"/tmp"));
        assert!(!inst.server.is_within(b"/dev/null", b"/tmp"));
        assert!(!inst.server.is_within(b"/tmp", b"/tmp/foo"));
        assert!(inst.server.is_within(b"/tmp", b"/tmp"));
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
        let qids = inst
            .server
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
        inst.server.clunk(&inst.next_meta(), fid(1));
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
        inst.server.clunk(&inst.next_meta(), fid(1));
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
        inst.server.clunk(&inst.next_meta(), fid(1));
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
            inst.server.clunk(&inst.next_meta(), fid(1));
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
            inst.server.clunk(&inst.next_meta(), fid(2));
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
            inst.server.clunk(&inst.next_meta(), fid(3));
            verify_closed(&mut inst, fid(3));
            inst.server
                .walk(&inst.next_meta(), fid(0), fid(4), &[b"dir", b"file"])
                .unwrap();
            verify_file(&mut inst, fid(4), b"dir/file");
            let st = inst.server.stat(&inst.next_meta(), fid(4)).unwrap();
            assert_eq!(st.name(), b"file");
            assert_eq!(st.mode().unwrap() & type_bits, FileType::empty());
            assert_eq!(st.mode().unwrap() & setid_bits, FileType::empty());
            inst.server.clunk(&inst.next_meta(), fid(4));
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
        inst.server.clunk(&inst.next_meta(), fid(1));
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
        inst.server.clunk(&inst.next_meta(), fid(2));
        verify_closed(&mut inst, fid(2));
    }
}
