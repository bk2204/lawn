use lawn_constants::Error;
use num_derive::FromPrimitive;
use std::any::Any;
use std::fs;
#[cfg(feature = "unix")]
use std::os::unix::fs::FileTypeExt;
use std::time::SystemTime;

#[cfg(feature = "unix")]
pub mod libc;

/// The kind of file.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum QIDKind {
    Directory = 0o04,
    Regular = 0o10,
    FIFO = 0o01,
    Symlink = 0o12,
    BlockDevice = 0o06,
    CharacterDevice = 0o02,
    Socket = 0o14,
    Authentication = 0xfe,
    Unknown = 0xff,
}

impl QIDKind {
    /// Compute the kind of file from a `FileType`.
    #[cfg(unix)]
    fn from_filetype(ft: rustix::fs::FileType) -> Self {
        match ft {
            rustix::fs::FileType::Socket => Self::Socket,
            rustix::fs::FileType::Symlink => Self::Symlink,
            rustix::fs::FileType::BlockDevice => Self::BlockDevice,
            rustix::fs::FileType::CharacterDevice => Self::CharacterDevice,
            rustix::fs::FileType::Fifo => Self::FIFO,
            rustix::fs::FileType::Directory => Self::Directory,
            rustix::fs::FileType::RegularFile => Self::Regular,
            _ => Self::Unknown,
        }
    }

    /// Compute the kind of file from a `stat` call.
    #[cfg(unix)]
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        let ft = metadata.file_type();
        if ft.is_fifo() {
            Self::FIFO
        } else if ft.is_socket() {
            Self::Socket
        } else if ft.is_block_device() {
            Self::BlockDevice
        } else if ft.is_char_device() {
            Self::CharacterDevice
        } else if ft.is_dir() {
            Self::Directory
        } else if ft.is_symlink() {
            Self::Symlink
        } else {
            Self::Unknown
        }
    }
}

/// A unique identifier for a file that persists over the life of file on disk.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct QID {
    kind: QIDKind,
    dev: u64,
    ino: u64,
}

impl Default for QID {
    fn default() -> QID {
        Self {
            kind: QIDKind::Unknown,
            dev: u64::MAX,
            ino: u64::MAX,
        }
    }
}

impl QID {
    /// Create this unique identifier from a kind of file, a device, and an inode number.
    pub fn new(kind: QIDKind, dev: u64, ino: u64) -> QID {
        Self { kind, dev, ino }
    }

    /// Return the kind of file represented by this `QID`.
    pub fn kind(&self) -> QIDKind {
        self.kind
    }

    /// Return the device number.
    pub fn dev(&self) -> u64 {
        self.dev
    }

    /// Return the inode number.
    pub fn ino(&self) -> u64 {
        self.ino
    }
}

/// A unique identifier for an file or request, chosen by the server (which in some cases comes
/// from the client).
///
/// Note that this can represent both an open file and a closed file.  Initially, the file is
/// closed, and it is opened by an explicit request.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct FID {
    id: u64,
}

impl FID {
    /// Create a new file identifier.
    pub const fn new(id: u64) -> FID {
        Self { id }
    }

    /// Return the 64-bit integer representing this file number.
    pub const fn to_u64(&self) -> u64 {
        self.id
    }
}

/// A request tag.
///
/// This is generally used by 9P-based protocols and ignored by SFTP-based protocols.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Tag {
    id: u64,
}

impl Tag {
    /// Create a new tag.
    pub const fn new(id: u64) -> Tag {
        Self { id }
    }

    /// Return the 64-bit integer representing this tag.
    pub const fn to_u64(&self) -> u64 {
        self.id
    }
}

/// The kind of 9P protocol in use.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum Plan9Type {
    /// This is the original 9P2000 protocol.
    Original,
    /// This is the Unix-based 9P2000.u protocol.
    Unix,
    /// This is the Linux-based 9P2000.L protocol.
    Linux,
}

/// The kind of SFTP protocol in use.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum SFTPType {
    /// This is version 3 of the SFTP protocol.
    V3,
}

/// The kind of SFTP extensions in use.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[non_exhaustive]
pub enum SFTPExtensions {
    OpenSSHPosixRenameV1,
    OpenSSHReversedSymlink,
    OpenSSHHardlinkV1,
    OpenSSHFsyncV1,
}

/// The kind of protocol in use.
#[derive(Copy, Clone, Debug)]
pub enum ProtocolType<'a> {
    Plan9(Plan9Type),
    SFTP(SFTPType, &'a [SFTPExtensions]),
    Other(Option<&'a dyn Any>),
}

/// Metadata about a request.
#[derive(Clone, Debug)]
pub struct Metadata<'a> {
    tag: Tag,
    command: u64,
    proto: ProtocolType<'a>,
    proto_extra: Option<u128>,
    efficient: bool,
}

impl<'a> Metadata<'a> {
    pub fn new(
        tag: Tag,
        command: u64,
        proto: ProtocolType<'a>,
        proto_extra: Option<u128>,
        efficient: bool,
    ) -> Metadata<'a> {
        Self {
            tag,
            command,
            proto,
            proto_extra,
            efficient,
        }
    }

    pub fn command(&self) -> u64 {
        self.command
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn protocol(&self) -> ProtocolType<'a> {
        self.proto
    }

    pub fn protocol_extra_data(&self) -> Option<u128> {
        self.proto_extra
    }

    /// Optimize for efficiency.
    ///
    /// This flag controls whether the request needs any valid QID data.
    pub fn efficient(&self) -> bool {
        self.efficient
    }

    fn needs_valid_qid(&self) -> bool {
        self.efficient
    }
}

type Result<T> = std::result::Result<T, Error>;

bitflags! {
    pub struct OpenMode: u32 {
        const O_RDONLY = 0x00;
        const O_WRONLY = 0x01;
        const O_RDWR = 0x02;
        const O_ACCMODE = 0x03;
        const O_CREAT = 0o100;
        const O_EXCL = 0o200;
        const O_NOCTTY = 0o400;
        const O_TRUNC = 0o1000;
        const O_APPEND = 0o2000;
        const O_NONBLOCK = 0o4000;
        const O_LARGEFILE = 0o100000;
        const O_DIRECTORY = 0o200000;
        const O_NOFOLLOW = 0o400000;
    }

    pub struct FileType: u32 {
        const S_IFMT  = 0o170000;
        const S_IFDIR = 0o040000;
        const S_IFCHR = 0o020000;
        const S_IFBLK = 0o060000;
        const S_IFREG = 0o100000;
        const S_IFIFO = 0o010000;
        const S_IFLNK = 0o120000;
        const S_IFSOCK = 0o140000;
        // We don't use these, but they need to exist so from_bits works properly.
        const S_ISUID = 0o4000;
        const S_ISGID = 0o2000;
        const S_ISVTX = 0o1000;
        const S_IRUSR = 0o0400;
        const S_IWUSR = 0o0200;
        const S_IXUSR = 0o0100;
        const S_IRGRP = 0o0040;
        const S_IWGRP = 0o0020;
        const S_IXGRP = 0o0010;
        const S_IROTH = 0o0004;
        const S_IWOTH = 0o0002;
        const S_IXOTH = 0o0001;
    }

    pub struct StatValidity: u64 {
        const MODE = 0x00000001;
        const NLINK = 0x00000002;
        const UID = 0x00000004;
        const GID = 0x00000008;
        const RDEV = 0x00000010;
        const ATIME = 0x00000020;
        const MTIME = 0x00000040;
        const CTIME = 0x00000080;
        const INODE = 0x00000100;
        const SIZE = 0x00000200;
        const BLOCKS = 0x00000400;
        const BTIME = 0x00000800;
        const GEN = 0x00001000;
        const DATA_VERSION = 0x00002000;
        const BASIC = 0x000007ff;
        const ALL = 0x00003fff;
    }
}

impl OpenMode {
    #[cfg(feature = "unix")]
    fn to_unix(self) -> rustix::fs::OFlags {
        let mut val = rustix::fs::OFlags::empty();
        if self.contains(Self::O_RDONLY) {
            val |= rustix::fs::OFlags::RDONLY;
        }
        if self.contains(Self::O_WRONLY) {
            val |= rustix::fs::OFlags::WRONLY;
        }
        if self.contains(Self::O_RDWR) {
            val |= rustix::fs::OFlags::RDWR;
        }
        if self.contains(Self::O_ACCMODE) {
            val |= rustix::fs::OFlags::ACCMODE;
        }
        if self.contains(Self::O_CREAT) {
            val |= rustix::fs::OFlags::CREATE;
        }
        if self.contains(Self::O_EXCL) {
            val |= rustix::fs::OFlags::EXCL;
        }
        if self.contains(Self::O_NOCTTY) {
            val |= rustix::fs::OFlags::NOCTTY;
        }
        if self.contains(Self::O_TRUNC) {
            val |= rustix::fs::OFlags::TRUNC;
        }
        if self.contains(Self::O_APPEND) {
            val |= rustix::fs::OFlags::APPEND;
        }
        if self.contains(Self::O_NONBLOCK) {
            val |= rustix::fs::OFlags::NONBLOCK;
        }
        if self.contains(Self::O_DIRECTORY) {
            val |= rustix::fs::OFlags::DIRECTORY;
        }
        if self.contains(Self::O_NOFOLLOW) {
            val |= rustix::fs::OFlags::NOFOLLOW;
        }
        val
    }
}

impl FileType {
    #[cfg(feature = "unix")]
    fn from_unix(mode: u32) -> Self {
        let kind = match rustix::fs::FileType::from_raw_mode(mode as rustix::fs::RawMode) {
            rustix::fs::FileType::Socket => Self::S_IFSOCK,
            rustix::fs::FileType::Symlink => Self::S_IFLNK,
            rustix::fs::FileType::BlockDevice => Self::S_IFBLK,
            rustix::fs::FileType::CharacterDevice => Self::S_IFCHR,
            rustix::fs::FileType::Fifo => Self::S_IFIFO,
            rustix::fs::FileType::Directory => Self::S_IFDIR,
            rustix::fs::FileType::RegularFile => Self::S_IFREG,
            _ => Self::from_bits(0).unwrap(),
        };
        let dmode = Self::from_bits(mode & 0o7777).unwrap();
        kind | dmode
    }

    #[allow(dead_code)]
    #[cfg(feature = "unix")]
    fn to_unix(&self) -> rustix::fs::RawMode {
        let ft = match *self & Self::S_IFMT {
            Self::S_IFSOCK => rustix::fs::FileType::Socket,
            Self::S_IFLNK => rustix::fs::FileType::Symlink,
            Self::S_IFBLK => rustix::fs::FileType::BlockDevice,
            Self::S_IFCHR => rustix::fs::FileType::CharacterDevice,
            Self::S_IFIFO => rustix::fs::FileType::Fifo,
            Self::S_IFDIR => rustix::fs::FileType::Directory,
            Self::S_IFREG => rustix::fs::FileType::RegularFile,
            _ => rustix::fs::FileType::Unknown,
        };
        ft.as_raw_mode() | (self.bits() & 0o7777) as rustix::fs::RawMode
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Stat {
    pub qid: QID,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: Option<u64>,
    pub rdev: Option<u64>,
    pub length: u64,
    pub blksize: u64,
    pub blocks: Option<u64>,
    pub atime_sec: Option<u64>,
    pub atime_nsec: Option<u64>,
    pub mtime_sec: Option<u64>,
    pub mtime_nsec: Option<u64>,
    pub ctime_sec: Option<u64>,
    pub ctime_nsec: Option<u64>,
    pub btime_sec: Option<u64>,
    pub btime_nsec: Option<u64>,
    pub gen: Option<u64>,
    pub data_version: Option<u64>,
}

impl Stat {
    #[allow(clippy::unnecessary_cast)]
    #[cfg(all(feature = "unix", not(target_os = "netbsd")))]
    fn from_unix(meta: &rustix::fs::Stat) -> Self {
        let mode = FileType::from_unix(meta.st_mode as u32);
        Self {
            qid: QID::new(QIDKind::Unknown, u64::MAX, u64::MAX),
            mode: mode.bits(),
            uid: meta.st_uid as u32,
            gid: meta.st_gid as u32,
            nlink: Some(meta.st_nlink as u64),
            rdev: Some(meta.st_rdev as u64),
            length: meta.st_size as u64,
            blksize: meta.st_blksize as u64,
            blocks: Some(meta.st_blocks as u64),
            atime_sec: Some(meta.st_atime as u64),
            atime_nsec: Some(meta.st_atime_nsec as u64),
            mtime_sec: Some(meta.st_mtime as u64),
            mtime_nsec: Some(meta.st_mtime_nsec as u64),
            ctime_sec: Some(meta.st_ctime as u64),
            ctime_nsec: Some(meta.st_ctime_nsec as u64),
            btime_sec: None,
            btime_nsec: None,
            gen: None,
            data_version: None,
        }
    }

    #[allow(clippy::unnecessary_cast)]
    #[cfg(all(feature = "unix", target_os = "netbsd"))]
    fn from_unix(meta: &rustix::fs::Stat) -> Self {
        let mode = FileType::from_unix(meta.st_mode as u32);
        Self {
            qid: QID::new(QIDKind::Unknown, u64::MAX, u64::MAX),
            mode: mode.bits(),
            uid: meta.st_uid as u32,
            gid: meta.st_gid as u32,
            nlink: Some(meta.st_nlink as u64),
            rdev: Some(meta.st_rdev as u64),
            length: meta.st_size as u64,
            blksize: meta.st_blksize as u64,
            blocks: Some(meta.st_blocks as u64),
            atime_sec: Some(meta.st_atime as u64),
            atime_nsec: Some(meta.st_atimensec as u64),
            mtime_sec: Some(meta.st_mtime as u64),
            mtime_nsec: Some(meta.st_mtimensec as u64),
            ctime_sec: Some(meta.st_ctime as u64),
            ctime_nsec: Some(meta.st_ctimensec as u64),
            btime_sec: None,
            btime_nsec: None,
            gen: None,
            data_version: None,
        }
    }
}

#[derive(FromPrimitive, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum LockKind {
    Read = 0,
    Write = 1,
}

#[derive(FromPrimitive, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum LockCommand {
    ReadLock = 0,
    WriteLock = 1,
    Unlock = 2,
}

impl From<LockKind> for LockCommand {
    fn from(kind: LockKind) -> Self {
        match kind {
            LockKind::Read => Self::ReadLock,
            LockKind::Write => Self::WriteLock,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum LockStatus {
    Ok = 0,
    Blocked = 1,
    Error = 2,
    Grace = 3,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Lock {
    pub kind: LockKind,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub qid: QID,
    pub offset: u64,
    pub kind: u8,
    pub name: Vec<u8>,
    pub extension: Option<Vec<u8>>,
    pub file_type: FileType,
    pub size: u64,
    pub metadata: fs::Metadata,
}

/// The interface to store and access files.
///
/// This is based around the joint needs of 9P and SFTP, and so the interface reflects that.
/// Users which are interested in a more Unix-like interface will probably find most of the
/// 9P2000.L-like interfaces more useful, along with some of the SFTP-based interfaces.
///
/// Implementations of this trait are free to perform optimizations depending on the protocol.  For
/// example, SFTP does not require the `kind` field of the QID field, so it will generally be set
/// to `QIDKind::Unknown`.
pub trait Backend {
    /// Create a handle to authenticate to this mount point.
    ///
    /// `afid` represents an `FID` to use to authenticate.  `uname` is the username and `nuname` is
    /// the user ID, if any.  `aname` is the resource to access.  Returns the `QID` for `afid`.
    ///
    /// The FID used to authenticate can be passed to `read` and `write` to perform an
    /// authenticator-specific authentication protocol.
    fn auth(
        &self,
        meta: &Metadata,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID>;
    /// Attach a mount point to `fid`.
    ///
    /// `afid` represents an `FID` to use to authenticate if it is `Some`, which should have been
    /// previously passed to `auth`.  If it is `None`, authentication is anonymous or controlled at
    /// a higher-level protocol.
    ///
    /// `uname` is the username and `nuname` is the user ID, if any.  `aname` is the resource to
    /// access.  Returns the `QID` for `fid`.
    fn attach(
        &self,
        meta: &Metadata,
        fid: FID,
        afid: Option<FID>,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID>;
    /// Invalidates `fid`.
    ///
    /// This indicates that the given `FID` is no longer needed and that the server should free
    /// resources with it.
    fn clunk(&self, meta: &Metadata, fid: FID) -> Result<()>;
    /// Invalidates all outstanding `FID` values.
    ///
    /// This indicates that the server should free resources associated with all file identifiers.
    fn clunk_all(&self, meta: &Metadata) -> Result<()>;
    /// Abort the operation associated with `Tag`.
    ///
    /// This requests that the backend abort any in-progress operations with the given tag.  If
    /// the request has already completed, returns `Err(Error::ESRCH)`.  If this functionality is
    /// not implemented, returns `Err(Error::ENOSYS)`.
    fn flush(&self, meta: &Metadata, tag: Tag) -> Result<()>;
    /// Open a file associated with a `fid` using `mode` as permissions.
    ///
    /// `fid` should point to a file, which may or may not be open.
    ///
    /// On success, this function returns the `QID` for the file, and an I/O unit value.  If the
    /// I/O unit value is `Some`, it indicates the maximum number of bytes that are guaranteed to
    /// be read or written from the file without breaking it into multiple messages.  If it is
    /// `None`, no guarantees are provided.
    fn open(&self, meta: &Metadata, fid: FID, mode: OpenMode) -> Result<(QID, Option<u32>)>;
    /// Determine whether the file `fid` is open.
    ///
    /// If this `fid` is valid and is open, returns `Ok(true)`.  If it is valid and closed, returns
    /// `Ok(false)`.  If it is not valid, returns `Err(Error::EBADF)`.
    fn is_open(&self, meta: &Metadata, fid: FID) -> Result<bool>;
    /// Create a regular file with `name` under the directory `fid`, opening it, and saving the
    /// resulting file into `newfid`.
    ///
    /// `flags` represents the open mode flags, and `mode` is the set of permissions for the file
    /// to have.  `gid` is the group ID for this file.
    ///
    /// On success, this function returns the `QID` for the file, and an I/O unit value.  If the
    /// I/O unit value is `Some`, it indicates the maximum number of bytes that are guaranteed to
    /// be read or written from the file without breaking it into multiple messages.  If it is
    /// `None`, no guarantees are provided.
    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        meta: &Metadata,
        fid: FID,
        newfid: FID,
        name: &[u8],
        flags: OpenMode,
        mode: FileType,
        gid: Option<u32>,
    ) -> Result<(QID, Option<u32>)>;
    /// Read data from `fid`, which must be open, at the given offset, into `data`.
    ///
    /// On EOF, this returns 0.
    fn read(&self, meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32>;
    /// Write data to `fid`, which must be open, at the given offset, from `data`.
    fn write(&self, meta: &Metadata, fid: FID, offset: u64, data: &[u8]) -> Result<u32>;
    /// Remove the file specified by `fid`.
    ///
    /// Removes the specified file.  The `clunk` operation is issued separately by the server.
    fn remove(&self, meta: &Metadata, fid: FID) -> Result<()>;
    fn fsync(&self, meta: &Metadata, fid: FID);
    /// Walk a path starting at `fid`, using the components in `name`, and leave the result in
    /// `newfid`.
    ///
    /// This is one of the only two ways to resolve paths, which must be relative to an existing
    /// directory.  Directory separators are not permitted in `name` and will be rejected with
    /// `Err(Error::EINVAL)`.  However, `.` and `..` components are permitted, and if a user would
    /// escape the root, the path simply resolves to the root instead.  Returns a list of the `QID`
    /// for each component.
    fn walk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<Vec<QID>>;
    /// Walk a path starting at `fid`, using the components in `name`, and leave the result in
    /// `newfid`.
    ///
    /// The behaviour here is exactly the same as for `walk`, except that QIDs are not computed and
    /// attempts to escape the root may return `Err(Error::EACCES)`.  This is substantially more
    /// efficient than `walk` when possible.
    fn resolve(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<()>;
    /// Create a symlink in the directory `fid` with name `name`, pointing to `target`.
    ///
    /// The gid of the requesting user is `gid`, if known.
    fn symlink(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        target: &[u8],
        gid: Option<u32>,
    ) -> Result<QID>;
    /// Create a device in the directory `fid` with name `name` and mode `mode``.
    ///
    /// The device major and minor must be specified.
    ///
    /// The gid of the requesting user is `gid`, if known.
    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        mode: FileType,
        major: u32,
        minor: u32,
        gid: Option<u32>,
    ) -> Result<QID>;
    /// Rename the file at `fid` to `name`, which is under the directory `dfid`.
    fn rename(&self, meta: &Metadata, fid: FID, dfid: FID, name: &[u8]) -> Result<()>;
    /// Read the value of the symlink at `fid`.
    fn readlink(&self, meta: &Metadata, fid: FID) -> Result<Vec<u8>>;
    /// Canonicalize the path at `fid`.
    ///
    /// The resolved path is returned as a `Vec` of path segments.  If the operation would resolve
    /// to a path outside of the root, returns `Err(Error::EACCES)`.
    fn realpath(&self, meta: &Metadata, fid: FID) -> Result<Vec<Vec<u8>>>;
    fn pathname(&self, meta: &Metadata, fid: FID) -> Result<Vec<Vec<u8>>>;
    fn getattr(&self, meta: &Metadata, fid: FID, mask: StatValidity) -> Result<Stat>;
    /// Set the attributes for the given FID.
    ///
    /// Set the mode, UID, GID, or size if they are `Some`.  If the corresponding set option is set
    /// for a given time, set that time, either to the given time, or to the current time if it is
    /// `None`.  Note that the `set_atime` and `set_mtime` do not correspond to those bits in the
    /// protocol mask.
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<()>;
    fn xattrwalk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[u8]) -> Result<u64>;
    fn xattrcreate(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        size: u64,
        flags: u32,
    ) -> Result<()>;
    /// Read one or more directory entries from `fid`.
    ///
    /// The `offset` field must be 0 the first time this request has been made, and otherwise an
    /// offset returned from the last item in the immediately previous iteration of this function
    /// (the second item in the returned tuple).  `offsetf` returns the increment in offset for
    /// each directory entry that is processed.  `count` is the maximum number of bytes to
    /// serialize, and `lenf` provides the number of bytes to serialize each directory entry.
    ///
    /// On success, returns a `Vec` of entries; when iteration has completed, the `Vec` will be
    /// empty.
    fn readdir(
        &self,
        meta: &Metadata,
        fid: FID,
        offset: u64,
        count: u32,
        offsetf: Box<dyn FnMut(&DirEntry) -> usize>,
        lenf: Box<dyn FnMut(&DirEntry) -> usize>,
    ) -> Result<Vec<DirEntry>>;
    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<LockStatus>;
    #[allow(clippy::too_many_arguments)]
    fn getlock(
        &self,
        meta: &Metadata,
        fid: FID,
        kind: LockKind,
        start: u64,
        length: u64,
        proc_id: u32,
        client_id: &[u8],
    ) -> Result<Lock>;
    fn link(&self, meta: &Metadata, dfid: FID, fid: FID, nane: &[u8]) -> Result<()>;
    fn mkdir(
        &self,
        meta: &Metadata,
        dfid: FID,
        name: &[u8],
        mode: FileType,
        gid: Option<u32>,
    ) -> Result<QID>;
    fn renameat(
        &self,
        meta: &Metadata,
        olddirfid: FID,
        oldname: &[u8],
        newdirfid: FID,
        newname: &[u8],
    ) -> Result<()>;
    fn unlinkat(&self, meta: &Metadata, dirfd: FID, name: &[u8], flags: u32) -> Result<()>;
}
