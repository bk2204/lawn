use crate::server::{
    DirEntry, FileType, LinuxOpenMode, LinuxStat, LinuxStatValidity, Lock, LockCommand, LockKind,
    LockStatus, Metadata, SimpleOpenMode, Stat, Tag, FID, QID,
};
use lawn_constants::Error;
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::SystemTime;

type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "unix")]
pub mod libc;

/// The interface to store and access files.
pub trait Backend {
    fn version(&self, meta: &Metadata, max_size: u32, version: &[u8]) -> Result<(u32, Vec<u8>)>;
    fn auth(
        &self,
        meta: &Metadata,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID>;
    fn attach(
        &self,
        meta: &Metadata,
        fid: FID,
        afid: FID,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Result<QID>;
    fn clunk(&self, meta: &Metadata, fid: FID) -> Result<()>;
    fn clunk_all(&self, meta: &Metadata) -> Result<()>;
    fn flush(&self, meta: &Metadata, tag: Tag) -> Result<()>;
    fn open(&self, meta: &Metadata, fid: FID, mode: SimpleOpenMode) -> Result<(QID, u32)>;
    fn lopen(&self, meta: &Metadata, fid: FID, flags: LinuxOpenMode) -> Result<(QID, u32)>;
    fn create(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        perm: FileType,
        mode: SimpleOpenMode,
        extension: Option<&[u8]>,
    ) -> Result<(QID, u32)>;
    #[allow(clippy::too_many_arguments)]
    fn lcreate(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        flags: u32,
        mode: u32,
        gid: u32,
    ) -> Result<(QID, u32)>;
    fn read(&self, meta: &Metadata, fid: FID, offset: u64, data: &mut [u8]) -> Result<u32>;
    fn write(&self, meta: &Metadata, fid: FID, offset: u64, data: &[u8]) -> Result<u32>;
    /// Remove the file specified by `fid`.
    ///
    /// Removes the specified file.  The `clunk` operation is issued separately by the server.
    fn remove(&self, meta: &Metadata, fid: FID) -> Result<()>;
    fn fsync(&self, meta: &Metadata, fid: FID);
    fn stat(&self, meta: &Metadata, fid: FID) -> Result<Box<dyn Stat>>;
    fn wstat(&self, meta: &Metadata, fid: FID, stat: &dyn Stat) -> Result<()>;
    fn walk(&self, meta: &Metadata, fid: FID, newfid: FID, name: &[&[u8]]) -> Result<Vec<QID>>;
    fn symlink(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        target: &[u8],
        gid: u32,
    ) -> Result<QID>;
    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        meta: &Metadata,
        fid: FID,
        name: &[u8],
        mode: u32,
        major: u32,
        minor: u32,
        gid: u32,
    ) -> Result<QID>;
    fn rename(&self, meta: &Metadata, fid: FID, dfid: FID, name: &[u8]) -> Result<()>;
    fn readlink(&self, meta: &Metadata, fid: FID) -> Result<Vec<u8>>;
    fn getattr(&self, meta: &Metadata, fid: FID, mask: LinuxStatValidity) -> Result<LinuxStat>;
    /// Set the attributes for the given FID.
    ///
    /// Set the mode, UID, GID, or size if they are `Some`.  If the corresponding set option is set
    /// for a given time, set that time, either to the given time, or to the current time if it is
    /// `None`.  Note that the `set_atime` and `set_mtime` do not correspond to those bits in the
    /// protocol mask.
    ///
    /// This is only implemented in the 9P2000.L protocol.
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
    fn readdir(&self, meta: &Metadata, fid: FID, offset: u64, count: u32) -> Result<Vec<DirEntry>>;
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
    fn mkdir(&self, meta: &Metadata, dfid: FID, name: &[u8], mode: u32, gid: u32) -> Result<QID>;
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

pub trait ToIdentifier: Ord {
    fn to_identifier(&self) -> Vec<u8>;
}

impl<T: Ord + AsRef<[u8]>> ToIdentifier for T {
    fn to_identifier(&self) -> Vec<u8> {
        self.as_ref().into()
    }
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub enum FIDKind<AH: ToIdentifier, FH: ToIdentifier, DH: ToIdentifier, SH: ToIdentifier> {
    Auth(AH),
    File(FH),
    Dir(DH),
    Symlink(SH),
    Special(SH),
}

impl<AH: ToIdentifier, FH: ToIdentifier, DH: ToIdentifier, SH: ToIdentifier>
    FIDKind<AH, FH, DH, SH>
{
    fn file_kind(&self) -> FileKind {
        match self {
            FIDKind::Auth(_) => FileKind::Auth,
            FIDKind::File(_) => FileKind::File,
            FIDKind::Dir(_) => FileKind::Dir,
            FIDKind::Symlink(_) => FileKind::Symlink,
            FIDKind::Special(_) => FileKind::Special,
        }
    }

    fn identifier(&self) -> Vec<u8> {
        match self {
            FIDKind::Auth(a) => a.to_identifier(),
            FIDKind::File(f) => f.to_identifier(),
            FIDKind::Dir(d) => d.to_identifier(),
            FIDKind::Symlink(s) => s.to_identifier(),
            FIDKind::Special(s) => s.to_identifier(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub enum FileKind {
    Auth = 0x08,
    File = 0x00,
    Dir = 0x80,
    Symlink = 0x02,
    Special = 0xff,
}

impl FileKind {
    #[cfg(feature = "unix")]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::FileTypeExt;

        let ft = metadata.file_type();
        if ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device() {
            Self::Special
        } else if ft.is_dir() {
            Self::Dir
        } else if ft.is_symlink() {
            Self::Symlink
        } else {
            Self::File
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct QIDStorage {
    kind: FileKind,
    data: Vec<u8>,
}

#[derive(Default)]
pub struct QIDMapper {
    next: AtomicU64,
    tree: Mutex<BTreeMap<QIDStorage, u64>>,
}

impl QIDMapper {
    pub fn new() -> QIDMapper {
        Self {
            next: AtomicU64::new(0),
            tree: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn qid<AH: ToIdentifier, FH: ToIdentifier, DH: ToIdentifier, SH: ToIdentifier>(
        &self,
        fid: &FIDKind<AH, FH, DH, SH>,
    ) -> QID {
        self.qid_from_vec(fid.file_kind(), fid.identifier())
    }

    pub fn qid_from_value<T: ToIdentifier>(&self, kind: FileKind, fid: &T) -> QID {
        self.qid_from_vec(kind, fid.to_identifier())
    }

    pub fn qid_from_id(&self, kind: FileKind, id: &[u8]) -> QID {
        self.qid_from_vec(kind, id.to_vec())
    }

    pub fn qid_from_vec(&self, kind: FileKind, id: Vec<u8>) -> QID {
        let storage = QIDStorage { kind, data: id };
        let id = {
            let mut g = self.tree.lock().unwrap();
            *g.entry(storage)
                .or_insert_with(|| self.next.fetch_add(1, Ordering::AcqRel))
        };
        let mut qid = QID([0u8; 13]);
        qid.0[0] = kind as u8;
        qid.0[5..13].copy_from_slice(&id.to_le_bytes());
        qid
    }
}
