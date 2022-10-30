use super::{Backend, FIDKind, FileKind, QIDMapper, Result, ToIdentifier};
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
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirEntryExt, FileExt, FileTypeExt, MetadataExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

trait MaybeIDInfo {
    fn id_info(&self) -> Option<&dyn IDInfo>;
}

impl<AH: ToIdentifier> MaybeIDInfo for FIDKind<AH, FileID, FileID, OpaqueFileID> {
    fn id_info(&self) -> Option<&dyn IDInfo> {
        match self {
            FIDKind::File(f) => Some(f),
            FIDKind::Dir(f) => Some(f),
            FIDKind::Special(f) => Some(f),
            FIDKind::Symlink(f) => Some(f),
            FIDKind::Auth(_) => None,
        }
    }
}

trait IDInfo {
    fn dev(&self) -> u64;
    fn ino(&self) -> u64;
    fn file(&self) -> Option<Arc<File>>;
    fn dir(&self) -> Option<Arc<File>>;
    fn path(&self) -> Option<&[u8]>;
    fn full_path(&self) -> &[u8];
}

struct FileID {
    dev: u64,
    ino: u64,
    file: Arc<File>,
    dir: Option<Arc<File>>,
    path: Option<Vec<u8>>,
    full_path: Vec<u8>,
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
            .then_with(|| self.file.as_raw_fd().cmp(&other.file.as_raw_fd()))
    }
}

impl ToIdentifier for FileID {
    fn to_identifier(&self) -> Vec<u8> {
        let mut buf = [0u8; 8 + 8];
        buf[0..8].copy_from_slice(&self.dev.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ino.to_le_bytes());
        buf.into()
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
        Some(self.file.clone())
    }
    fn dir(&self) -> Option<Arc<File>> {
        self.dir.clone()
    }
    fn path(&self) -> Option<&[u8]> {
        self.path.as_deref()
    }
    fn full_path(&self) -> &[u8] {
        &self.full_path
    }
}

struct OpaqueFileID {
    dev: u64,
    ino: u64,
    dir: Arc<File>,
    path: Vec<u8>,
    full_path: Vec<u8>,
}

impl Eq for OpaqueFileID {}

impl PartialEq for OpaqueFileID {
    fn eq(&self, other: &OpaqueFileID) -> bool {
        self.cmp(other) == cmp::Ordering::Equal
    }
}

impl PartialOrd for OpaqueFileID {
    fn partial_cmp(&self, other: &OpaqueFileID) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OpaqueFileID {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.dev
            .cmp(&other.dev)
            .then_with(|| self.ino.cmp(&other.ino))
            .then_with(|| self.dir.as_raw_fd().cmp(&other.dir.as_raw_fd()))
            .then_with(|| self.path.cmp(&other.path))
    }
}

impl ToIdentifier for OpaqueFileID {
    fn to_identifier(&self) -> Vec<u8> {
        let mut buf = [0u8; 8 + 8];
        buf[0..8].copy_from_slice(&self.dev.to_le_bytes());
        buf[8..16].copy_from_slice(&self.ino.to_le_bytes());
        buf.into()
    }
}

impl IDInfo for OpaqueFileID {
    fn dev(&self) -> u64 {
        self.dev
    }
    fn ino(&self) -> u64 {
        self.ino
    }
    fn file(&self) -> Option<Arc<File>> {
        None
    }
    fn dir(&self) -> Option<Arc<File>> {
        Some(self.dir.clone())
    }
    fn path(&self) -> Option<&[u8]> {
        Some(&*self.path)
    }
    fn full_path(&self) -> &[u8] {
        &self.full_path
    }
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
    count: usize,
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
pub struct LibcBackend<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Send + Sync> {
    max_size: u32,
    auth: A,
    fid: HashMap<FID, FIDKind<AH, FileID, FileID, OpaqueFileID>>,
    dir_offsets: HashMap<FID, HashMap<(u64, ProtocolVersion), Option<Arc<Mutex<fs::ReadDir>>>>>,
    qidmapper: QIDMapper,
    root: RwLock<Option<Vec<u8>>>,
    logger: Arc<dyn Logger + Send + Sync>,
}

impl<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Send + Sync> LibcBackend<A, AH> {
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
        path: &[u8],
        flags: i32,
        mode: u32,
        dirfd: Option<RawFd>,
        stored_dirfd: Option<Arc<File>>,
        stored_path: Option<&[u8]>,
        dir_full_path: &[u8],
    ) -> Result<FIDKind<AH, FileID, FileID, OpaqueFileID>> {
        let (full_path, fd) = match dirfd {
            Some(_) => {
                let mut full_path = dir_full_path.to_vec();
                full_path.extend([b'/']);
                full_path.extend(path);
                self.maybe_open_symlink(&full_path, flags, mode)?
            }
            None => self.maybe_open_symlink(dir_full_path, flags, mode)?,
        };
        let f = unsafe { File::from_raw_fd(fd) };
        let metadata = f.metadata()?;
        let path = if stored_path.is_some() {
            full_path.file_name().map(|c| c.as_bytes().to_vec())
        } else {
            None
        };
        if metadata.is_file() {
            Ok(FIDKind::File(FileID {
                dev: metadata.dev(),
                ino: metadata.ino(),
                file: Arc::new(f),
                dir: stored_dirfd,
                path,
                full_path: full_path.into_os_string().into_vec(),
            }))
        } else if metadata.is_dir() {
            Ok(FIDKind::Dir(FileID {
                dev: metadata.dev(),
                ino: metadata.ino(),
                file: Arc::new(f),
                dir: stored_dirfd,
                path,
                full_path: full_path.into_os_string().into_vec(),
            }))
        } else {
            let st = LinuxStat::from_metadata(&metadata);
            trace!(
                self.logger,
                "opening file: unknown type {:?}",
                st.and_then(|st| LinuxFileType::from_bits(st.mode))
            );
            Err(Error::EOPNOTSUPP)
        }
    }

    fn clone_with_mode(
        &self,
        f: &FIDKind<AH, FileID, FileID, OpaqueFileID>,
        flags: i32,
        mode: Option<u32>,
    ) -> Result<FIDKind<AH, FileID, FileID, OpaqueFileID>> {
        let (file, dir, path, full_path): (Option<RawFd>, _, Option<&[u8]>, _) = match &f {
            FIDKind::File(f) => (
                Some(f.file.as_raw_fd()),
                f.dir.clone(),
                f.path.as_deref(),
                &*f.full_path,
            ),
            FIDKind::Dir(f) => (
                Some(f.file.as_raw_fd()),
                f.dir.clone(),
                f.path.as_deref(),
                &*f.full_path,
            ),
            FIDKind::Symlink(f) => (None, Some(f.dir.clone()), Some(&f.path), &*f.full_path),
            _ => return Err(Error::EOPNOTSUPP),
        };
        let fname = if let Some(file) = file {
            self.file_name(&file)
        } else {
            full_path.to_vec()
        };
        self.open_file(
            &*fname,
            flags,
            mode.unwrap_or(0),
            None,
            dir,
            path,
            full_path,
        )
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
    fn ftruncate<F: AsRawFd>(&self, f: &F, size: u64) -> Result<()> {
        with_error(|| unsafe { libc::ftruncate64(f.as_raw_fd(), size as i64) })?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn ftruncate<F: AsRawFd>(&self, f: &F, size: u64) -> Result<()> {
        with_error(|| unsafe { libc::ftruncate(f.as_raw_fd(), size as i64) })?;
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
                let qid = self.qidmapper.qid(&fk);
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
                st.dir = None;
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
        let dev = idi.dev();
        let dg = self.dir_offsets.guard();
        let idg;
        let new;
        let iter = if offset == 0 {
            new = Arc::new(Mutex::new(fs::read_dir(OsStr::from_bytes(
                idi.full_path(),
            ))?));
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
        for entry in riter {
            let entry = entry?;
            // TODO: map to proper type.
            let qid = self.qid_from_dev_ino(FileKind::File, dev, entry.ino());
            let de = DirEntry {
                qid,
                kind: 0,
                offset: offset + 1,
                name: entry.file_name().into_vec(),
            };
            let len = match kind {
                ProtocolVersion::Original => PlainStat::FIXED_SIZE + entry.file_name().len(),
                ProtocolVersion::Unix => UnixStat::FIXED_SIZE + entry.file_name().len(),
                ProtocolVersion::Linux => de.len(),
            };
            if msg_size + len > max_size {
                let offmap = match self.dir_offsets.try_insert(fid, HashMap::default(), &dg) {
                    Ok(map) => map,
                    Err(e) => e.current,
                };
                let og = offmap.guard();
                offmap.insert((offset, kind), Some(iter.clone()), &og);
                return Ok(res);
            }
            res.push(de);
            offset += match kind {
                ProtocolVersion::Linux => 1,
                _ => len as u64,
            };
            msg_size += len;
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

impl<A: Authenticator<SessionHandle = AH>, AH: ToIdentifier + Send + Sync> Backend
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
        let qid = self.qidmapper.qid(&handle);
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
            let file = self.open_file(location, libc::O_RDONLY, 0, None, None, None, location)?;
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
        let qid = self.qidmapper.qid(&file);
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
        let (dir, dir_path) = match self.fid.get(&fid, &g) {
            Some(FIDKind::Dir(dh)) => (dh.file.clone(), &*dh.full_path),
            _ => return Err(Error::ENOTDIR),
        };
        let mut full_path = dir_path.to_vec();
        full_path.extend([b'/']);
        full_path.extend(name);
        let cpath = CString::new(name).map_err(|_| Error::EINVAL)?;
        let (mmode, mdev) = match (
            perm & !(FileType::DMACCMODE | FileType::DMSETUID | FileType::DMSETGID),
            extension,
        ) {
            (FileType::DMDIR, None) => {
                trace!(
                    self.logger,
                    "9P create: directory: {}",
                    (&*full_path).as_log_str()
                );
                with_error(|| unsafe { libc::mkdirat(dir.as_raw_fd(), cpath.as_ptr(), mode) })?;
                trace!(
                    self.logger,
                    "9P create: directory creation OK, opening file"
                );
                let file = self.open_file(
                    name,
                    libc::O_RDONLY,
                    0,
                    Some(dir.as_raw_fd()),
                    Some(dir),
                    Some(name),
                    dir_path,
                )?;
                let qid = self.qidmapper.qid(&file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (FileType::DMSYMLINK, Some(dest)) => {
                trace!(
                    self.logger,
                    "9P create: symlink: {} {}",
                    (&*full_path).as_log_str(),
                    dest.as_log_str()
                );
                let cdest = CString::new(dest).map_err(|_| Error::EINVAL)?;
                with_error(|| unsafe {
                    libc::symlinkat(cdest.as_ptr(), dir.as_raw_fd(), cpath.as_ptr())
                })?;
                let (dev, ino) = self.fstatat_dev_ino(&dir.as_raw_fd(), name, false)?;
                let file = FIDKind::<AH, FileID, FileID, OpaqueFileID>::Symlink(OpaqueFileID {
                    dev,
                    ino,
                    dir,
                    path: name.to_vec(),
                    full_path,
                });
                let qid = self.qidmapper.qid(&file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (x, None) if x == FileType::empty() => {
                trace!(
                    self.logger,
                    "9P create: file: {}",
                    (&*full_path).as_log_str()
                );
                let omode = omode.to_unix().ok_or(Error::EINVAL)? | libc::O_CREAT | libc::O_EXCL;
                let file = self.open_file(
                    name,
                    omode,
                    mode,
                    Some(dir.as_raw_fd()),
                    Some(dir),
                    Some(name),
                    dir_path,
                )?;
                let qid = self.qidmapper.qid(&file);
                self.fid.insert(fid, file, &g);
                return Ok((qid, 0));
            }
            (FileType::DMDEVICE, Some(kind)) => self.parse_major_minor(kind)?,
            (FileType::DMSOCKET, None) => (libc::S_IFSOCK, 0),
            (FileType::DMNAMEDPIPE, None) => (libc::S_IFIFO, 0),
            _ => return Err(Error::EINVAL),
        };
        trace!(
            self.logger,
            "9P create: mknod: {}",
            (&*full_path).as_log_str()
        );
        with_error(|| unsafe { libc::mknodat(dir.as_raw_fd(), cpath.as_ptr(), mmode, mdev) })?;
        let (dev, ino) = self.fstatat_dev_ino(&dir.as_raw_fd(), name, false)?;
        let file = FIDKind::<AH, FileID, FileID, OpaqueFileID>::Special(OpaqueFileID {
            dev,
            ino,
            dir,
            path: name.to_vec(),
            full_path,
        });
        let qid = self.qidmapper.qid(&file);
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
        let (dir, dir_path) = match self.fid.get(&fid, &g) {
            Some(FIDKind::Dir(dh)) => (dh.file.clone(), &*dh.full_path),
            _ => return Err(Error::EINVAL),
        };
        let flags = libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_EXCL;
        let file = self.open_file(
            name,
            flags,
            mode,
            Some(dir.as_raw_fd()),
            Some(dir),
            Some(name),
            dir_path,
        )?;
        let qid = self.qidmapper.qid(&file);
        Ok((qid, 0))
    }
    fn read(&self, meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32> {
        if data.len() > u32::MAX as usize {
            return Err(Error::EINVAL);
        }
        let g = self.fid.guard();
        match self.fid.get(&fid, &g) {
            Some(FIDKind::File(fh)) => match fh.file.read_at(data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            Some(FIDKind::Dir(dh)) => {
                let entries = self.do_readdir(fid, offset, meta.protocol, data.len() as u32)?;
                let mut size = 0;
                let path = dh.full_path();
                for entry in entries {
                    let mut path = PathBuf::from(OsStr::from_bytes(path));
                    path.push(OsStr::from_bytes(&entry.name));
                    let fsmeta = fs::symlink_metadata(&path)?;
                    match meta.protocol {
                        ProtocolVersion::Original => {
                            let mut st = PlainStat::from_metadata(&fsmeta).ok_or(Error::EIO)?;
                            st.qid = entry.qid;
                            st.qid.0[0] = (st.mode >> 24) as u8;
                            st.size += entry.name.len() as u16;
                            st.name = entry.name;
                            let st = st.to_bytes().ok_or(Error::EIO)?;
                            data[size..size + st.len()].copy_from_slice(&st);
                            size += st.len();
                        }
                        ProtocolVersion::Unix | ProtocolVersion::Linux => {
                            let mut st = UnixStat::from_metadata(&fsmeta).ok_or(Error::EIO)?;
                            st.qid = entry.qid;
                            st.qid.0[0] = (st.mode >> 24) as u8;
                            st.size += entry.name.len() as u16;
                            st.name = entry.name;
                            let st = st.to_bytes().ok_or(Error::EIO)?;
                            data[size..size + st.len()].copy_from_slice(&st);
                            size += st.len();
                        }
                    }
                }
                Ok(size as u32)
            }
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
        match self.fid.get(&fid, &g) {
            Some(FIDKind::File(fh)) => match fh.file.write_at(data, offset) {
                Ok(len) => Ok(len as u32),
                Err(e) => Err(e.into()),
            },
            Some(f) => {
                trace!(self.logger, "9P write: invalid type {:?}", f.file_kind());
                Err(Error::EBADF)
            }
            None => {
                trace!(self.logger, "9P write: no such descriptor");
                Err(Error::EBADF)
            }
        }
    }
    fn remove(&self, _meta: &Metadata, fid: FID) -> Result<()> {
        trace!(self.logger, "9P remove: fid {}", fid);
        let g = self.fid.guard();
        let result = match self.fid.get(&fid, &g) {
            Some(fk) => {
                self.fid.remove(&fid, &g);
                let (path, full_path, dir, is_dir) = match &fk {
                    FIDKind::File(fh) => (fh.path(), fh.full_path(), fh.dir(), false),
                    FIDKind::Dir(dh) => (dh.path(), dh.full_path(), dh.dir(), true),
                    FIDKind::Symlink(sh) => (sh.path(), sh.full_path(), sh.dir(), false),
                    FIDKind::Special(sh) => (sh.path(), sh.full_path(), sh.dir(), false),
                    _ => return Err(Error::EOPNOTSUPP),
                };
                trace!(
                    self.logger,
                    "9P remove: kind {:?} path {:?} has_dir {} is_dir {}",
                    fk.file_kind(),
                    path,
                    dir.is_some(),
                    is_dir
                );
                match (path, dir, is_dir) {
                    (Some(path), Some(dir), true) => {
                        let cpath = CString::new(path).map_err(|_| Error::EINVAL)?;
                        with_error(|| unsafe {
                            libc::unlinkat(dir.as_raw_fd(), cpath.as_ptr(), libc::AT_REMOVEDIR)
                        })
                    }
                    (Some(path), Some(dir), false) => {
                        let cpath = CString::new(path).map_err(|_| Error::EINVAL)?;
                        with_error(|| unsafe { libc::unlinkat(dir.as_raw_fd(), cpath.as_ptr(), 0) })
                    }
                    (_, _, true) => {
                        let cpath = CString::new(full_path).map_err(|_| Error::EINVAL)?;
                        with_error(|| unsafe { libc::rmdir(cpath.as_ptr()) })
                    }
                    (_, _, false) => {
                        let cpath = CString::new(full_path).map_err(|_| Error::EINVAL)?;
                        with_error(|| unsafe { libc::unlink(cpath.as_ptr()) })
                    }
                }
            }
            None => Err(Error::EBADF),
        };
        result.map(|_| ())
    }
    fn fsync(&self, _meta: &Metadata, fid: FID) {
        let g = self.fid.guard();
        if let Some(FIDKind::File(fh)) = self.fid.get(&fid, &g) {
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
                let qid = self.qidmapper.qid(desc);
                let (path, full_path) = match desc {
                    FIDKind::File(fh) => (fh.path(), &*fh.full_path),
                    FIDKind::Dir(dh) => (dh.path(), &*dh.full_path),
                    FIDKind::Symlink(sh) => (sh.path(), &*sh.full_path),
                    FIDKind::Special(sh) => (sh.path(), &*sh.full_path),
                    FIDKind::Auth(_) => {
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
                        }))
                    }
                };
                let fsmeta = fs::symlink_metadata(OsStr::from_bytes(full_path))?;
                let mut pst = PlainStat::from_metadata(&fsmeta).ok_or(Error::ENOMEM)?;
                pst.qid = self.qid_from_dev_ino(FileKind::File, fsmeta.dev(), fsmeta.ino());
                pst.qid.0[0] = (pst.mode >> 24) as u8;
                let root = self.root.read().unwrap();
                pst.name = if let Some(ref p) = *root {
                    if p == full_path {
                        vec![b'/']
                    } else {
                        path.unwrap_or_default().to_vec()
                    }
                } else {
                    path.unwrap_or_default().to_vec()
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
                let qid = self.qidmapper.qid(desc);
                let (path, full_path, is_symlink) = match desc {
                    FIDKind::File(fh) => (fh.path(), &*fh.full_path, false),
                    FIDKind::Dir(dh) => (dh.path(), &*dh.full_path, false),
                    FIDKind::Symlink(sh) => (sh.path(), &*sh.full_path, true),
                    FIDKind::Special(sh) => (sh.path(), &*sh.full_path, true),
                    FIDKind::Auth(_) => {
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
                        }))
                    }
                };
                let fsmeta = fs::symlink_metadata(OsStr::from_bytes(full_path))?;
                let mut ust = UnixStat::from_metadata(&fsmeta).ok_or(Error::ENOMEM)?;
                ust.qid = self.qid_from_dev_ino(FileKind::File, fsmeta.dev(), fsmeta.ino());
                ust.qid.0[0] = (ust.mode >> 24) as u8;
                let root = self.root.read().unwrap();
                ust.name = if let Some(ref p) = *root {
                    if p == full_path {
                        vec![b'/']
                    } else {
                        path.unwrap_or_default().to_vec()
                    }
                } else {
                    path.unwrap_or_default().to_vec()
                };
                ust.size += ust.name.len() as u16;
                if is_symlink {
                    ust.extension = match fs::read_link(OsStr::from_bytes(full_path)) {
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
                let desc = match self.fid.get(&fid, &g) {
                    Some(desc) => desc,
                    None => return Err(Error::EBADF),
                };
                let (file, full_path, is_symlink) = match desc {
                    FIDKind::File(fh) => (Some(fh.file.clone()), &*fh.full_path, false),
                    FIDKind::Dir(dh) => (Some(dh.file.clone()), &*dh.full_path, false),
                    FIDKind::Symlink(sh) => (None, &*sh.full_path, true),
                    FIDKind::Special(sh) => (None, &*sh.full_path, false),
                    FIDKind::Auth(_) => return Err(Error::EOPNOTSUPP),
                };
                let full_path = full_path.to_vec();
                std::mem::drop(g);
                if !stat.kind().is_flush()
                    || !stat.dev().unwrap_or(u32::MAX).is_flush()
                    || (!is_symlink && stat.extension().is_some())
                {
                    return Err(Error::EINVAL);
                }
                let metadata = match file {
                    Some(ref f) => f.metadata()?,
                    None => fs::metadata(OsStr::from_bytes(&full_path))?,
                };
                let mut ac = AtomicCommitter::new();
                let mut dest_full_path: PathBuf = OsString::from_vec(full_path.clone()).into();
                if !stat.name().is_empty() {
                    dest_full_path = dest_full_path.parent().unwrap().into();
                    dest_full_path.push(OsStr::from_bytes(stat.name()));
                    let fp1 = OsString::from_vec(full_path.clone());
                    let fp2 = OsString::from_vec(full_path.clone());
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
                        let c = CString::new(full_path.clone()).map_err(|_| Error::EINVAL)?;
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
                        let c = CString::new(full_path.clone()).map_err(|_| Error::EINVAL)?;
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
                        let c = CString::new(full_path.clone()).map_err(|_| Error::EINVAL)?;
                        ac.add(
                            Box::new(move || {
                                match file {
                                    Some(ref f) => with_error(|| unsafe {
                                        libc::ftruncate(f.as_raw_fd(), len as libc::off_t)
                                    })?,
                                    None => with_error(|| unsafe {
                                        libc::truncate(c.as_ptr(), len as libc::off_t)
                                    })?,
                                };
                                Ok(())
                            }),
                            None,
                        );
                    }
                }
                match ac.commit() {
                    Ok(()) => {
                        if dest_full_path.as_os_str().as_bytes() != full_path {
                            let g = self.fid.guard();
                            match self.fid.get(&fid, &g) {
                                Some(FIDKind::Dir(d)) => {
                                    self.fid.insert(
                                        fid,
                                        FIDKind::Dir(FileID {
                                            dev: d.dev,
                                            ino: d.ino,
                                            file: d.file.clone(),
                                            dir: d.dir.clone(),
                                            path: Some(stat.name().into()),
                                            full_path: dest_full_path.into_os_string().into_vec(),
                                        }),
                                        &g,
                                    );
                                }
                                Some(FIDKind::File(f)) => {
                                    self.fid.insert(
                                        fid,
                                        FIDKind::File(FileID {
                                            dev: f.dev,
                                            ino: f.ino,
                                            file: f.file.clone(),
                                            dir: f.dir.clone(),
                                            path: Some(stat.name().into()),
                                            full_path: dest_full_path.into_os_string().into_vec(),
                                        }),
                                        &g,
                                    );
                                }
                                Some(FIDKind::Symlink(s)) => {
                                    self.fid.insert(
                                        fid,
                                        FIDKind::Symlink(OpaqueFileID {
                                            dev: s.dev,
                                            ino: s.ino,
                                            dir: s.dir.clone(),
                                            path: stat.name().into(),
                                            full_path: dest_full_path.into_os_string().into_vec(),
                                        }),
                                        &g,
                                    );
                                }
                                Some(FIDKind::Special(s)) => {
                                    self.fid.insert(
                                        fid,
                                        FIDKind::Special(OpaqueFileID {
                                            dev: s.dev,
                                            ino: s.ino,
                                            dir: s.dir.clone(),
                                            path: stat.name().into(),
                                            full_path: dest_full_path.into_os_string().into_vec(),
                                        }),
                                        &g,
                                    );
                                }
                                _ => (),
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
        let (file, kind, full_path, dir, path, dev, ino) = match self.fid.get(&fid, &g) {
            Some(FIDKind::File(fh)) => (
                Some(fh.file.clone()),
                FileKind::File,
                &*fh.full_path,
                fh.dir(),
                fh.path(),
                fh.dev(),
                fh.ino(),
            ),
            Some(FIDKind::Dir(dh)) => (
                Some(dh.file.clone()),
                FileKind::Dir,
                &*dh.full_path,
                dh.dir(),
                dh.path(),
                dh.dev(),
                dh.ino(),
            ),
            Some(FIDKind::Symlink(sh)) => (
                None,
                FileKind::Symlink,
                &*sh.full_path,
                sh.dir(),
                sh.path(),
                sh.dev(),
                sh.ino(),
            ),
            Some(FIDKind::Special(sh)) => (
                None,
                FileKind::Special,
                &*sh.full_path,
                sh.dir(),
                sh.path(),
                sh.dev(),
                sh.ino(),
            ),
            _ => return Err(Error::EOPNOTSUPP),
        };
        let full_path = full_path.to_owned();
        let path = path.map(|p| p.to_owned());
        std::mem::drop(g);
        if name.is_empty() {
            let g = self.fid.guard();
            match (kind, &file) {
                (FileKind::File, Some(f)) => self.fid.insert(
                    newfid,
                    FIDKind::File(FileID {
                        dev,
                        ino,
                        file: f.clone(),
                        dir,
                        path,
                        full_path,
                    }),
                    &g,
                ),
                (FileKind::Dir, Some(f)) => self.fid.insert(
                    newfid,
                    FIDKind::Dir(FileID {
                        dev,
                        ino,
                        file: f.clone(),
                        dir,
                        path,
                        full_path,
                    }),
                    &g,
                ),
                (FileKind::Symlink, _) => self.fid.insert(
                    newfid,
                    FIDKind::Symlink(OpaqueFileID {
                        dev,
                        ino,
                        dir: dir.unwrap(),
                        path: path.unwrap(),
                        full_path,
                    }),
                    &g,
                ),
                (FileKind::Special, _) => self.fid.insert(
                    newfid,
                    FIDKind::Special(OpaqueFileID {
                        dev,
                        ino,
                        dir: dir.unwrap(),
                        path: path.unwrap(),
                        full_path,
                    }),
                    &g,
                ),
                // This is an auth descriptor.
                _ => return Err(Error::EOPNOTSUPP),
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
                (&*full_path).as_log_str(),
            );
            let fst = self.fstatat_dev_ino(&file.as_raw_fd(), b"", false)?;
            let lst = self.lstat_dev_ino(&full_path)?;
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
        let full_path: PathBuf = OsString::from_vec(full_path.to_vec()).into();
        let buf = [0u8; 0];
        let mut st = WalkState {
            root,
            component: &buf,
            dir,
            file,
            kind: FileKind::File,
            next_full_path: full_path.clone(),
            full_path,
            count: 0,
            dev,
            ino,
        };
        let mut result = Vec::new();
        for (i, component) in name.iter().enumerate() {
            st.count = i;
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
            if i != name.len() - 1 {
                st.full_path = st.next_full_path.clone();
                st.dir = st.file;
                st.file = None;
            }
        }
        if result.len() == name.len() {
            let path = st
                .full_path
                .as_os_str()
                .as_bytes()
                .rsplitn(2, |x| *x == b'/')
                .next();
            let g = self.fid.guard();
            match (st.kind, &st.file, &st.dir) {
                (FileKind::File, Some(f), d) => self.fid.insert(
                    newfid,
                    FIDKind::File(FileID {
                        dev,
                        ino,
                        file: f.clone(),
                        dir: d.clone(),
                        path: path.map(ToOwned::to_owned),
                        full_path: st.full_path.into_os_string().into_vec(),
                    }),
                    &g,
                ),
                (FileKind::Dir, Some(f), d) => self.fid.insert(
                    newfid,
                    FIDKind::Dir(FileID {
                        dev,
                        ino,
                        file: f.clone(),
                        dir: d.clone(),
                        path: path.map(ToOwned::to_owned),
                        full_path: st.full_path.into_os_string().into_vec(),
                    }),
                    &g,
                ),
                (FileKind::Symlink, _, Some(dir)) => self.fid.insert(
                    newfid,
                    FIDKind::Symlink(OpaqueFileID {
                        dev,
                        ino,
                        dir: dir.clone(),
                        path: path.map(ToOwned::to_owned).unwrap(),
                        full_path: st.full_path.into_os_string().into_vec(),
                    }),
                    &g,
                ),
                (FileKind::Special, _, Some(dir)) => self.fid.insert(
                    newfid,
                    FIDKind::Special(OpaqueFileID {
                        dev,
                        ino,
                        dir: dir.clone(),
                        path: path.map(ToOwned::to_owned).unwrap(),
                        full_path: st.full_path.into_os_string().into_vec(),
                    }),
                    &g,
                ),
                // This is possibly an auth descriptor.  How we got here is unknown.
                (kind, file, dir) => {
                    trace!(
                        self.logger,
                        "9P walk: walk failed, {} components, kind {:?}, has_file {}, has_dir {}",
                        result.len(),
                        kind,
                        file.is_some(),
                        dir.is_some()
                    );
                    return Err(Error::EOPNOTSUPP);
                }
            };
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
        let file = idi.file().ok_or(Error::EINVAL)?;
        let target = if target.starts_with(b"/") {
            let mut full_path = root.clone();
            full_path.extend(target);
            full_path
        } else {
            target.to_vec()
        };
        let ctarget = CString::new(target).map_err(|_| Error::EINVAL)?;
        let cname = CString::new(name.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe {
            libc::symlinkat(ctarget.as_ptr(), file.as_raw_fd(), cname.as_ptr())
        })?;
        let (dev, ino) = self.fstatat_dev_ino(&file.as_raw_fd(), name, false)?;
        Ok(self.qid_from_dev_ino(FileKind::Symlink, dev, ino))
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
        let olddir = oldidi.dir().ok_or(Error::ENOTDIR)?;
        let oldname = oldidi.path().ok_or(Error::EOPNOTSUPP)?;
        trace!(self.logger, "9P rename: verified old directory info");
        let newdir = newidi.file().ok_or(Error::ENOTDIR)?;
        trace!(self.logger, "9P rename: verified new directory info");
        let coldname = CString::new(oldname.to_vec()).map_err(|_| Error::EINVAL)?;
        let cnewname = CString::new(newname.to_vec()).map_err(|_| Error::EINVAL)?;
        trace!(self.logger, "9P rename: verified path info");
        let new_path = newname.to_vec();
        let mut new_full_path = newidi.full_path().to_vec();
        new_full_path.push(b'/');
        new_full_path.extend(newname);
        with_error(|| unsafe {
            libc::renameat(
                olddir.as_raw_fd(),
                coldname.as_ptr(),
                newdir.as_raw_fd(),
                cnewname.as_ptr(),
            )
        })?;
        match self.fid.get(&fid, &g) {
            Some(FIDKind::Dir(d)) => {
                self.fid.insert(
                    fid,
                    FIDKind::Dir(FileID {
                        dev: d.dev,
                        ino: d.ino,
                        file: d.file.clone(),
                        dir: newidi.file(),
                        path: Some(new_path),
                        full_path: new_full_path,
                    }),
                    &g,
                );
            }
            Some(FIDKind::File(f)) => {
                self.fid.insert(
                    fid,
                    FIDKind::File(FileID {
                        dev: f.dev,
                        ino: f.ino,
                        file: f.file.clone(),
                        dir: newidi.file(),
                        path: Some(new_path),
                        full_path: new_full_path,
                    }),
                    &g,
                );
            }
            Some(FIDKind::Symlink(s)) => {
                self.fid.insert(
                    fid,
                    FIDKind::Symlink(OpaqueFileID {
                        dev: s.dev,
                        ino: s.ino,
                        dir: newidi.file().unwrap(),
                        path: new_path,
                        full_path: new_full_path,
                    }),
                    &g,
                );
            }
            Some(FIDKind::Special(s)) => {
                self.fid.insert(
                    fid,
                    FIDKind::Special(OpaqueFileID {
                        dev: s.dev,
                        ino: s.ino,
                        dir: newidi.file().unwrap(),
                        path: new_path,
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
        let dest = fs::read_link(OsStr::from_bytes(idi.full_path()))?
            .into_os_string()
            .into_vec();
        Ok(dest)
    }
    fn getattr(&self, _meta: &Metadata, fid: FID, _mask: LinuxStatValidity) -> Result<LinuxStat> {
        let g = self.fid.guard();
        let idi = match self.fid.get(&fid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::EOPNOTSUPP)?,
            None => return Err(Error::EBADF),
        };
        let full_path = idi.full_path();
        let meta = fs::metadata(OsStr::from_bytes(full_path))?;
        let ft = if meta.file_type().is_dir() {
            FileKind::Dir
        } else if meta.file_type().is_symlink() {
            FileKind::Symlink
        } else if meta.file_type().is_file() {
            FileKind::File
        } else {
            FileKind::Special
        };
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
        let dir = idi.dir();
        let path = idi.path();
        let (fd, cpath) = match (dir, path) {
            (Some(dir), Some(path)) => (
                dir.as_raw_fd(),
                CString::new(path.to_vec()).map_err(|_| Error::EINVAL)?,
            ),
            _ => (
                -1,
                CString::new(idi.full_path().to_vec()).map_err(|_| Error::EINVAL)?,
            ),
        };
        if let Some(mode) = mode {
            let flag = if file.is_none() {
                libc::AT_SYMLINK_NOFOLLOW
            } else {
                0
            };
            with_error(|| unsafe { libc::fchmodat(fd, cpath.as_ptr(), mode & 0o7777, flag) })?;
        }
        if uid.is_some() || gid.is_some() {
            with_error(|| unsafe {
                libc::fchownat(
                    fd,
                    cpath.as_ptr(),
                    uid.unwrap_or(-1i32 as libc::uid_t),
                    gid.unwrap_or(-1i32 as libc::gid_t),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            })?;
        }
        if let Some(size) = size {
            match file {
                Some(f) => self.ftruncate(&f, size)?,
                None => return Err(Error::EINVAL),
            };
        }
        if atime.is_some() || mtime.is_some() {
            let times = [
                self.system_time_to_timespec(atime, set_atime),
                self.system_time_to_timespec(mtime, set_mtime),
            ];
            with_error(|| unsafe { libc::utimensat(fd, cpath.as_ptr(), times.as_ptr(), 0) })?;
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
        let dfile = didi.file().ok_or(Error::ENOTDIR)?;
        let dir = idi.dir().ok_or(Error::EOPNOTSUPP)?;
        let path = idi.path().ok_or(Error::EOPNOTSUPP)?;
        let cpath = CString::new(path.to_vec()).map_err(|_| Error::EINVAL)?;
        let cname = CString::new(name.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe {
            libc::linkat(
                dir.as_raw_fd(),
                cpath.as_ptr(),
                dfile.as_raw_fd(),
                cname.as_ptr(),
                0,
            )
        })?;
        Ok(())
    }
    fn mkdir(&self, _meta: &Metadata, dfid: FID, name: &[u8], mode: u32, _gid: u32) -> Result<QID> {
        self.assert_valid_path_component(name, false)?;
        let g = self.fid.guard();
        let didi = match self.fid.get(&dfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let dir = didi.file().ok_or(Error::ENOTDIR)?;
        let mode = mode & 0o7777;
        let cname = CString::new(name.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe { libc::mkdirat(dir.as_raw_fd(), cname.as_ptr(), mode) })?;
        let (dev, ino) = self.fstatat_dev_ino(&dir.as_raw_fd(), name, false)?;
        Ok(self.qid_from_dev_ino(FileKind::Symlink, dev, ino))
    }
    fn renameat(
        &self,
        _meta: &Metadata,
        olddirfid: FID,
        oldname: &[u8],
        newdirfid: FID,
        newname: &[u8],
    ) -> Result<()> {
        self.assert_valid_path_component(oldname, false)?;
        self.assert_valid_path_component(newname, false)?;
        let g = self.fid.guard();
        let oldidi = match self.fid.get(&olddirfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let newidi = match self.fid.get(&newdirfid, &g) {
            Some(idi) => idi.id_info().ok_or(Error::ENOTDIR)?,
            None => return Err(Error::EBADF),
        };
        let olddir = oldidi.file().ok_or(Error::ENOTDIR)?;
        let newdir = newidi.file().ok_or(Error::ENOTDIR)?;
        let coldname = CString::new(oldname.to_vec()).map_err(|_| Error::EINVAL)?;
        let cnewname = CString::new(newname.to_vec()).map_err(|_| Error::EINVAL)?;
        with_error(|| unsafe {
            libc::renameat(
                olddir.as_raw_fd(),
                coldname.as_ptr(),
                newdir.as_raw_fd(),
                cnewname.as_ptr(),
            )
        })?;
        Ok(())
    }
    fn unlinkat(&self, _meta: &Metadata, _dirfd: FID, _name: &[u8], _flags: u32) -> Result<()> {
        // TODO: implement unlinkat.
        Err(Error::EOPNOTSUPP)
    }
}

#[cfg(test)]
mod tests {
    use super::{IDInfo, LibcBackend};
    use crate::auth::{AuthenticationInfo, Authenticator};
    use crate::backend::{Backend, FIDKind, ToIdentifier};
    use crate::server::{
        FileType, LinuxFileType, LinuxOpenMode, LinuxStatValidity, Metadata, PlainStat,
        ProtocolVersion, SimpleOpenMode, Tag, UnixStat, FID,
    };
    use lawn_constants::logger::{LogFormat, LogLevel};
    use lawn_constants::Error;
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
        file: Arc<File>,
        path: &Path,
        f: F,
    ) {
        let (dev, ino) = inst
            .server
            .fstatat_dev_ino(&file.as_raw_fd(), b"", false)
            .unwrap();
        let meta = std::fs::symlink_metadata(path).unwrap();
        assert_eq!((dev, ino), (meta.dev(), meta.ino()), "same file");
        assert!(f(&meta.file_type()), "file is of correct type");
    }

    fn verify_dir(inst: &mut TestInstance, fid: FID, path: Option<&[u8]>) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(FIDKind::Dir(d)) = entry {
            let mut full_path = inst.dir.path().to_owned();
            full_path.push(OsStr::from_bytes(path.unwrap_or_default()));
            assert_ne!(d.path(), Some(b".." as &[u8]), "not dot-dot");
            assert_eq!(
                fs::canonicalize(OsStr::from_bytes(d.full_path())).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            match path {
                Some(path) => {
                    if path.is_empty() {
                        assert_eq!(full_path, inst.dir.path(), "path is root");
                    } else {
                        assert_eq!(
                            d.path().unwrap(),
                            full_path.file_name().unwrap().as_bytes(),
                            "path is correct"
                        );
                    }
                }
                None => assert!(d.path().is_none(), "path is empty"),
            }
            if let Some(d) = d.dir() {
                verify_file_is_path(&inst, d, full_path.parent().unwrap(), |f| f.is_dir())
            }
            if let Some(f) = d.file() {
                verify_file_is_path(&inst, f, &full_path, |f| f.is_dir())
            }
        } else {
            panic!("Not a directory");
        }
    }

    fn verify_file(inst: &mut TestInstance, fid: FID, path: &[u8]) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(FIDKind::File(d)) = entry {
            let mut full_path = inst.dir.path().to_owned();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(d.path(), Some(b".." as &[u8]), "not dot-dot");
            assert_eq!(
                fs::canonicalize(OsStr::from_bytes(d.full_path())).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            assert_eq!(
                d.path().unwrap(),
                full_path.file_name().unwrap().as_bytes(),
                "path is correct"
            );
            if let Some(d) = d.dir() {
                verify_file_is_path(&inst, d, full_path.parent().unwrap(), |f| f.is_dir())
            } else {
                panic!("No directory!");
            }
            if let Some(f) = d.file() {
                verify_file_is_path(&inst, f, &full_path, |f| f.is_file())
            } else {
                panic!("No file!");
            }
        } else {
            panic!("Not a file");
        }
    }

    fn verify_symlink(inst: &mut TestInstance, fid: FID, path: &[u8], dest: &[u8]) {
        let g = inst.server.fid.guard();
        let entry = inst.server.fid.get(&fid, &g);
        if let Some(FIDKind::Symlink(s)) = entry {
            let mut full_path = inst.dir.path().to_owned();
            full_path.push(OsStr::from_bytes(path));
            assert_ne!(s.path(), Some(b".." as &[u8]), "not dot-dot");
            assert_eq!(
                fs::canonicalize(OsStr::from_bytes(s.full_path())).unwrap(),
                fs::canonicalize(&full_path).unwrap(),
                "full path is correct"
            );
            assert_eq!(
                s.path().unwrap(),
                full_path.file_name().unwrap().as_bytes(),
                "path is correct"
            );
            if let Some(d) = s.dir() {
                verify_file_is_path(&inst, d, full_path.parent().unwrap(), |f| f.is_dir())
            } else {
                panic!("No directory!");
            }
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
        for ver in [
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            let mut inst = instance(ver);
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
                if ver == ProtocolVersion::Linux {
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
        for ver in [
            ProtocolVersion::Original,
            ProtocolVersion::Unix,
            ProtocolVersion::Linux,
        ] {
            let mut inst = instance(ver);
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
        verify_file(&mut inst, fid(1), b"dir/file");
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
        verify_file(&mut inst, fid(1), b"dir/file");
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
        verify_file(&mut inst, fid(1), b"dir/file");
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
        inst.server
            .rename(&inst.next_meta(), fid(2), fid(4), b"baz")
            .unwrap();
        verify_file(&mut inst, fid(2), b"other-dir/nested-dir/baz");
        inst.server.clunk(&inst.next_meta(), fid(1)).unwrap();
        verify_closed(&mut inst, fid(1));
        inst.server.clunk(&inst.next_meta(), fid(2)).unwrap();
        verify_closed(&mut inst, fid(2));
        inst.server.clunk(&inst.next_meta(), fid(3)).unwrap();
        verify_closed(&mut inst, fid(3));
        inst.server.clunk(&inst.next_meta(), fid(4)).unwrap();
        verify_closed(&mut inst, fid(4));
    }

    #[test]
    fn files_and_directories_std() {
        for ver in [ProtocolVersion::Original, ProtocolVersion::Unix] {
            let mut inst = instance(ver);
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
