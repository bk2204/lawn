use crate::backend::Backend;
use lawn_constants::Error;
use lawn_fs::backend as fsbackend;
use num_derive::FromPrimitive;
use std::convert::TryInto;
use std::fmt;
#[cfg(feature = "unix")]
use std::fs;
#[cfg(feature = "unix")]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

pub use lawn_fs::backend::OpenMode as LinuxOpenMode;

mod implementation;

pub use implementation::{Server, ServerError};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Tag(pub [u8; 2]);

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Tag(0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl From<Tag> for fsbackend::Tag {
    fn from(t: Tag) -> fsbackend::Tag {
        fsbackend::Tag::new(u16::from_le_bytes(t.0) as u64)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct FID(pub [u8; 4]);

impl fmt::Display for FID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "FID(0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl From<FID> for fsbackend::FID {
    fn from(f: FID) -> fsbackend::FID {
        fsbackend::FID::new(u32::from_le_bytes(f.0) as u64)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct QID(pub [u8; 13]);

impl fmt::Display for QID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "QID(0x{:02x}:", self.0[0])?;
        for b in &self.0[1..5] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ":")?;
        for b in &self.0[5..13] {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

pub trait IsFlush {
    fn is_flush(&self) -> bool;
}

impl IsFlush for QID {
    fn is_flush(&self) -> bool {
        self.0.iter().all(|x| *x == 0xff)
    }
}

impl IsFlush for u16 {
    fn is_flush(&self) -> bool {
        *self == u16::MAX
    }
}

impl IsFlush for u32 {
    fn is_flush(&self) -> bool {
        *self == u32::MAX
    }
}

impl IsFlush for u64 {
    fn is_flush(&self) -> bool {
        *self == u64::MAX
    }
}

impl IsFlush for Vec<u8> {
    fn is_flush(&self) -> bool {
        self.is_empty()
    }
}

pub struct Metadata {
    pub protocol: ProtocolVersion,
    pub tag: Tag,
}

impl<'a> From<&'a Metadata> for fsbackend::Metadata<'a> {
    fn from(m: &'a Metadata) -> fsbackend::Metadata<'a> {
        fsbackend::Metadata::new(
            m.tag.into(),
            0,
            fsbackend::ProtocolType::Plan9(m.protocol.into()),
            None,
            false,
        )
    }
}

pub trait Stat: IsFlush {
    fn kind(&self) -> u16;
    fn dev(&self) -> Option<u32>;
    fn rdev(&self) -> Option<u64>;
    fn qid(&self) -> &QID;
    fn mode(&self) -> Option<FileType>;
    fn lmode(&self) -> Option<LinuxFileType>;
    fn atime(&self) -> SystemTime;
    fn mtime(&self) -> SystemTime;
    fn ctime(&self) -> Option<SystemTime>;
    fn btime(&self) -> Option<SystemTime>;
    fn length(&self) -> u64;
    fn name(&self) -> &[u8];
    fn uid(&self) -> &[u8];
    fn gid(&self) -> &[u8];
    fn muid(&self) -> Option<&[u8]>;
    fn nuid(&self) -> Option<u32>;
    fn ngid(&self) -> Option<u32>;
    fn nmuid(&self) -> Option<u32>;
    fn nlink(&self) -> Option<u64>;
    fn extension(&self) -> Option<&[u8]>;
    fn to_bytes(&self) -> Option<Vec<u8>>;
}

pub struct PlainStat {
    pub size: u16,
    pub kind: u16,
    pub dev: u32,
    pub qid: QID,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: Vec<u8>,
    pub uid: Vec<u8>,
    pub gid: Vec<u8>,
    pub muid: Vec<u8>,
}

impl PlainStat {
    /// The size of all fixed quantities, including the string length headers.
    pub const FIXED_SIZE: usize = 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2;

    pub fn from_bytes(_size: u16, data: &[u8]) -> Option<Self> {
        let d = Deserializer::new(data);
        Some(Self {
            size: d.read_u16().ok()?,
            kind: d.read_u16().ok()?,
            dev: d.read_u32().ok()?,
            qid: d.read_qid().ok()?,
            mode: d.read_u32().ok()?,
            atime: d.read_u32().ok()?,
            mtime: d.read_u32().ok()?,
            length: d.read_u64().ok()?,
            name: d.read_string().ok()?.to_vec(),
            uid: d.read_string().ok()?.to_vec(),
            gid: d.read_string().ok()?.to_vec(),
            muid: d.read_string().ok()?.to_vec(),
        })
    }
}

impl IsFlush for PlainStat {
    fn is_flush(&self) -> bool {
        self.kind.is_flush()
            && self.dev.is_flush()
            && self.qid.is_flush()
            && self.mode.is_flush()
            && self.atime.is_flush()
            && self.length.is_flush()
            && self.name.is_flush()
            && self.uid.is_flush()
            && self.gid.is_flush()
            && self.muid.is_flush()
    }
}

impl Stat for PlainStat {
    fn kind(&self) -> u16 {
        self.kind
    }

    fn dev(&self) -> Option<u32> {
        Some(self.dev)
    }

    fn rdev(&self) -> Option<u64> {
        None
    }

    fn qid(&self) -> &QID {
        &self.qid
    }

    fn mode(&self) -> Option<FileType> {
        FileType::from_bits(self.mode)
    }

    fn lmode(&self) -> Option<LinuxFileType> {
        None
    }

    fn atime(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.atime.into())
    }

    fn mtime(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.mtime.into())
    }

    fn ctime(&self) -> Option<SystemTime> {
        None
    }

    fn btime(&self) -> Option<SystemTime> {
        None
    }

    fn length(&self) -> u64 {
        self.length
    }

    fn name(&self) -> &[u8] {
        &self.name
    }

    fn uid(&self) -> &[u8] {
        &self.uid
    }

    fn gid(&self) -> &[u8] {
        &self.gid
    }

    fn muid(&self) -> Option<&[u8]> {
        Some(&*self.muid)
    }

    fn nuid(&self) -> Option<u32> {
        None
    }

    fn ngid(&self) -> Option<u32> {
        None
    }

    fn nmuid(&self) -> Option<u32> {
        None
    }

    fn nlink(&self) -> Option<u64> {
        None
    }

    fn to_bytes(&self) -> Option<Vec<u8>> {
        let len =
            Self::FIXED_SIZE + self.name.len() + self.uid.len() + self.gid.len() + self.muid.len()
                - 2;
        let len: u16 = len.try_into().ok()?;
        let mut s = Serializer::new();
        s.write_u16(len);
        s.write_u16(self.kind);
        s.write_u32(self.dev);
        s.write_qid(self.qid);
        s.write_u32(self.mode);
        s.write_u32(self.atime);
        s.write_u32(self.mtime);
        s.write_u64(self.length);
        s.write_string(&self.name).ok()?;
        s.write_string(&self.uid).ok()?;
        s.write_string(&self.gid).ok()?;
        s.write_string(&self.muid).ok()?;
        Some(s.into_inner())
    }
    fn extension(&self) -> Option<&[u8]> {
        None
    }
}

pub struct UnixStat {
    pub size: u16,
    pub kind: u16,
    pub dev: u32,
    pub qid: QID,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: Vec<u8>,
    pub uid: Vec<u8>,
    pub gid: Vec<u8>,
    pub muid: Vec<u8>,
    pub extension: Vec<u8>,
    pub nuid: u32,
    pub ngid: u32,
    pub nmuid: u32,
}

impl UnixStat {
    /// The size of all fixed quantities, including the string length headers.
    pub const FIXED_SIZE: usize = 2 + 2 + 4 + 13 + 4 + 4 + 4 + 8 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4;

    pub fn from_bytes(_size: u16, data: &[u8]) -> Option<Self> {
        let d = Deserializer::new(data);
        Some(Self {
            size: d.read_u16().ok()?,
            kind: d.read_u16().ok()?,
            dev: d.read_u32().ok()?,
            qid: d.read_qid().ok()?,
            mode: d.read_u32().ok()?,
            atime: d.read_u32().ok()?,
            mtime: d.read_u32().ok()?,
            length: d.read_u64().ok()?,
            name: d.read_string().ok()?.to_vec(),
            uid: d.read_string().ok()?.to_vec(),
            gid: d.read_string().ok()?.to_vec(),
            muid: d.read_string().ok()?.to_vec(),
            extension: d.read_string().ok()?.to_vec(),
            nuid: d.read_u32().ok()?,
            ngid: d.read_u32().ok()?,
            nmuid: d.read_u32().ok()?,
        })
    }
}

impl IsFlush for UnixStat {
    fn is_flush(&self) -> bool {
        self.kind.is_flush()
            && self.dev.is_flush()
            && self.qid.is_flush()
            && self.mode.is_flush()
            && self.atime.is_flush()
            && self.length.is_flush()
            && self.name.is_flush()
            && self.uid.is_flush()
            && self.gid.is_flush()
            && self.muid.is_flush()
            && self.extension.is_flush()
            && self.nuid.is_flush()
            && self.ngid.is_flush()
            && self.nmuid.is_flush()
    }
}

impl Stat for UnixStat {
    fn kind(&self) -> u16 {
        self.kind
    }

    fn dev(&self) -> Option<u32> {
        Some(self.dev)
    }

    fn rdev(&self) -> Option<u64> {
        None
    }

    fn qid(&self) -> &QID {
        &self.qid
    }

    fn mode(&self) -> Option<FileType> {
        FileType::from_bits(self.mode)
    }

    fn lmode(&self) -> Option<LinuxFileType> {
        None
    }

    fn atime(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.atime.into())
    }

    fn mtime(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.mtime.into())
    }

    fn ctime(&self) -> Option<SystemTime> {
        None
    }

    fn btime(&self) -> Option<SystemTime> {
        None
    }

    fn length(&self) -> u64 {
        self.length
    }

    fn name(&self) -> &[u8] {
        &self.name
    }

    fn uid(&self) -> &[u8] {
        &self.uid
    }

    fn gid(&self) -> &[u8] {
        &self.gid
    }

    fn muid(&self) -> Option<&[u8]> {
        Some(&*self.muid)
    }

    fn nuid(&self) -> Option<u32> {
        Some(self.nuid)
    }

    fn ngid(&self) -> Option<u32> {
        Some(self.ngid)
    }

    fn nmuid(&self) -> Option<u32> {
        Some(self.nmuid)
    }

    fn nlink(&self) -> Option<u64> {
        None
    }

    fn extension(&self) -> Option<&[u8]> {
        if self.extension.is_empty() {
            None
        } else {
            Some(&self.extension)
        }
    }

    fn to_bytes(&self) -> Option<Vec<u8>> {
        let len = Self::FIXED_SIZE
            + self.name.len()
            + self.uid.len()
            + self.gid.len()
            + self.muid.len()
            + self.extension.len()
            - 2;
        let len: u16 = len.try_into().ok()?;
        let mut s = Serializer::new();
        s.write_u16(len);
        s.write_u16(self.kind);
        s.write_u32(self.dev);
        s.write_qid(self.qid);
        s.write_u32(self.mode);
        s.write_u32(self.atime);
        s.write_u32(self.mtime);
        s.write_u64(self.length);
        s.write_string(&self.name).ok()?;
        s.write_string(&self.uid).ok()?;
        s.write_string(&self.gid).ok()?;
        s.write_string(&self.muid).ok()?;
        s.write_string(&self.extension).ok()?;
        s.write_u32(self.nuid);
        s.write_u32(self.ngid);
        s.write_u32(self.nmuid);
        Some(s.into_inner())
    }
}

pub struct LinuxStat {
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

impl LinuxStat {
    pub fn from_fs(st: &fsbackend::Stat, qid: QID) -> Self {
        LinuxStat {
            qid,
            mode: st.mode,
            uid: st.uid,
            gid: st.gid,
            nlink: st.nlink,
            rdev: st.rdev,
            length: st.length,
            blksize: st.blksize,
            blocks: st.blocks,
            atime_sec: st.atime_sec,
            atime_nsec: st.atime_nsec,
            mtime_sec: st.mtime_sec,
            mtime_nsec: st.mtime_nsec,
            ctime_sec: st.ctime_sec,
            ctime_nsec: st.ctime_nsec,
            btime_sec: st.btime_sec,
            btime_nsec: st.btime_nsec,
            gen: st.gen,
            data_version: st.data_version,
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let d = Deserializer::new(data);
        let validity = LinuxStatValidity::from_bits(d.read_u64().ok()?)?;
        // This doesn't contain enough data to be useful.
        if !validity.contains(
            LinuxStatValidity::MODE
                | LinuxStatValidity::UID
                | LinuxStatValidity::GID
                | LinuxStatValidity::SIZE,
        ) {
            return None;
        }
        let (qid, mode, uid, gid, nlink, rdev, size, blksize, blocks) = (
            d.read_qid().ok()?,
            d.read_u32().ok()?,
            d.read_u32().ok()?,
            d.read_u32().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
        );
        let (
            atime_sec,
            atime_nsec,
            mtime_sec,
            mtime_nsec,
            ctime_sec,
            ctime_nsec,
            btime_sec,
            btime_nsec,
        ) = (
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
            d.read_u64().ok()?,
        );
        let (gen, data_version) = (d.read_u64().ok()?, d.read_u64().ok()?);
        Some(Self {
            qid,
            mode,
            uid,
            gid,
            nlink: if validity.contains(LinuxStatValidity::NLINK) {
                Some(nlink)
            } else {
                None
            },
            rdev: if validity.contains(LinuxStatValidity::RDEV) {
                Some(rdev)
            } else {
                None
            },
            length: size,
            blksize,
            blocks: if validity.contains(LinuxStatValidity::BLOCKS) {
                Some(blocks)
            } else {
                None
            },
            atime_sec: if validity.contains(LinuxStatValidity::ATIME) {
                Some(atime_sec)
            } else {
                None
            },
            atime_nsec: if validity.contains(LinuxStatValidity::ATIME) {
                Some(atime_nsec)
            } else {
                None
            },
            mtime_sec: if validity.contains(LinuxStatValidity::MTIME) {
                Some(mtime_sec)
            } else {
                None
            },
            mtime_nsec: if validity.contains(LinuxStatValidity::MTIME) {
                Some(mtime_nsec)
            } else {
                None
            },
            ctime_sec: if validity.contains(LinuxStatValidity::CTIME) {
                Some(ctime_sec)
            } else {
                None
            },
            ctime_nsec: if validity.contains(LinuxStatValidity::CTIME) {
                Some(ctime_nsec)
            } else {
                None
            },
            btime_sec: if validity.contains(LinuxStatValidity::BTIME) {
                Some(btime_sec)
            } else {
                None
            },
            btime_nsec: if validity.contains(LinuxStatValidity::BTIME) {
                Some(btime_nsec)
            } else {
                None
            },
            gen: if validity.contains(LinuxStatValidity::GEN) {
                Some(gen)
            } else {
                None
            },
            data_version: if validity.contains(LinuxStatValidity::DATA_VERSION) {
                Some(data_version)
            } else {
                None
            },
        })
    }

    fn write_optional(
        &self,
        val: Option<u64>,
        validity: &mut LinuxStatValidity,
        flag: LinuxStatValidity,
        s: &mut Serializer,
    ) {
        match val {
            Some(v) => {
                s.write_u64(v);
                *validity |= flag;
            }
            None => s.write_u64(0),
        }
    }

    fn write_time(
        &self,
        sec: Option<u64>,
        nsec: Option<u64>,
        validity: &mut LinuxStatValidity,
        flag: LinuxStatValidity,
        ser: &mut Serializer,
    ) {
        match (sec, nsec) {
            (Some(s), Some(n)) => {
                ser.write_u64(s);
                ser.write_u64(n);
                *validity |= flag;
            }
            _ => {
                ser.write_u64(0);
                ser.write_u64(0);
            }
        }
    }

    pub fn to_bytes(&self) -> (Vec<u8>, LinuxStatValidity) {
        let mut validity = LinuxStatValidity::UID
            | LinuxStatValidity::GID
            | LinuxStatValidity::MODE
            | LinuxStatValidity::SIZE
            | LinuxStatValidity::INODE;
        let mut s = Serializer::new();
        s.write_qid(self.qid);
        s.write_u32(self.mode);
        s.write_u32(self.uid);
        s.write_u32(self.gid);
        self.write_optional(self.nlink, &mut validity, LinuxStatValidity::NLINK, &mut s);
        self.write_optional(self.rdev, &mut validity, LinuxStatValidity::RDEV, &mut s);
        s.write_u64(self.length);
        s.write_u64(self.blksize);
        self.write_optional(
            self.blocks,
            &mut validity,
            LinuxStatValidity::BLOCKS,
            &mut s,
        );
        self.write_time(
            self.atime_sec,
            self.atime_nsec,
            &mut validity,
            LinuxStatValidity::ATIME,
            &mut s,
        );
        self.write_time(
            self.mtime_sec,
            self.mtime_nsec,
            &mut validity,
            LinuxStatValidity::MTIME,
            &mut s,
        );
        self.write_time(
            self.ctime_sec,
            self.ctime_nsec,
            &mut validity,
            LinuxStatValidity::CTIME,
            &mut s,
        );
        self.write_time(
            self.btime_sec,
            self.btime_nsec,
            &mut validity,
            LinuxStatValidity::BTIME,
            &mut s,
        );
        self.write_optional(self.gen, &mut validity, LinuxStatValidity::GEN, &mut s);
        self.write_optional(
            self.data_version,
            &mut validity,
            LinuxStatValidity::DATA_VERSION,
            &mut s,
        );
        (s.into_inner(), validity)
    }
}

pub struct DirEntry {
    pub qid: QID,
    pub offset: u64,
    pub kind: u8,
    pub name: Vec<u8>,
    pub extension: Option<Vec<u8>>,
    pub file_type: LinuxFileType,
    pub size: u64,
    pub metadata: fs::Metadata,
}

impl DirEntry {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        13 + 8 + 1 + 2 + self.name.len()
    }

    pub fn from_fs(de: &fsbackend::DirEntry, qid: QID) -> DirEntry {
        Self {
            qid,
            offset: de.offset,
            kind: de.kind,
            name: de.name.clone(),
            extension: de.extension.clone(),
            file_type: LinuxFileType::from_bits(de.file_type.bits()).unwrap(),
            size: de.size,
            metadata: de.metadata.clone(),
        }
    }
}

#[derive(FromPrimitive)]
pub enum LockKind {
    Read = 0,
    Write = 1,
}

#[derive(FromPrimitive)]
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

impl From<LockKind> for fsbackend::LockKind {
    fn from(kind: LockKind) -> Self {
        match kind {
            LockKind::Read => Self::Read,
            LockKind::Write => Self::Write,
        }
    }
}

impl From<fsbackend::LockKind> for LockKind {
    fn from(kind: fsbackend::LockKind) -> Self {
        match kind {
            fsbackend::LockKind::Read => Self::Read,
            fsbackend::LockKind::Write => Self::Write,
        }
    }
}

impl From<LockCommand> for fsbackend::LockCommand {
    fn from(kind: LockCommand) -> Self {
        match kind {
            LockCommand::ReadLock => Self::ReadLock,
            LockCommand::WriteLock => Self::WriteLock,
            LockCommand::Unlock => Self::Unlock,
        }
    }
}

#[derive(FromPrimitive, Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
enum ProtocolTag {
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    // 106 would be Terror, which is illegal.
    Rerror = 107,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Topen = 112,
    Ropen = 113,
    Tcreate = 114,
    Rcreate = 115,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
    Tstat = 124,
    Rstat = 125,
    Twstat = 126,
    Rwstat = 127,
}

pub enum LockStatus {
    Ok = 0,
    Blocked = 1,
    Error = 2,
    Grace = 3,
}

impl From<fsbackend::LockStatus> for LockStatus {
    fn from(kind: fsbackend::LockStatus) -> Self {
        match kind {
            fsbackend::LockStatus::Ok => Self::Ok,
            fsbackend::LockStatus::Blocked => Self::Blocked,
            fsbackend::LockStatus::Error => Self::Error,
            fsbackend::LockStatus::Grace => Self::Grace,
        }
    }
}

pub struct Lock {
    pub kind: LockKind,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: Vec<u8>,
}

impl From<fsbackend::Lock> for Lock {
    fn from(lock: fsbackend::Lock) -> Self {
        Self {
            kind: lock.kind.into(),
            start: lock.start,
            length: lock.length,
            proc_id: lock.proc_id,
            client_id: lock.client_id,
        }
    }
}

pub struct UnknownProtocolError;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ProtocolVersion {
    Original,
    Unix,
    Linux,
}

impl FromStr for ProtocolVersion {
    type Err = UnknownProtocolError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "9P2000" => Ok(ProtocolVersion::Original),
            "9P2000.u" => Ok(ProtocolVersion::Unix),
            "9P2000.L" => Ok(ProtocolVersion::Linux),
            _ => Err(UnknownProtocolError),
        }
    }
}

impl From<ProtocolVersion> for fsbackend::Plan9Type {
    fn from(p: ProtocolVersion) -> fsbackend::Plan9Type {
        match p {
            ProtocolVersion::Original => fsbackend::Plan9Type::Original,
            ProtocolVersion::Unix => fsbackend::Plan9Type::Unix,
            ProtocolVersion::Linux => fsbackend::Plan9Type::Linux,
        }
    }
}

impl ProtocolVersion {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Original => "9P2000",
            Self::Unix => "9P2000.u",
            Self::Linux => "9P2000.L",
        }
    }
}

bitflags! {
    pub struct SimpleOpenMode: u8 {
        const O_READ = 0x00;
        const O_WRITE = 0x01;
        const O_RDWR = 0x02;
        const O_EXEC = 0x03;
        const O_ACCMODE = 0x03;
        const O_TRUNC = 0x10;
    }

    pub struct FileType: u32 {
        const DMDIR =            0x80000000;
        const DMAPPEND =         0x40000000;
        const DMEXCL =           0x20000000;
        const DMMOUNT =          0x10000000;
        const DMAUTH =           0x08000000;
        const DMTMP =            0x04000000;
        const DMSYMLINK =        0x02000000;
        const DMDEVICE =         0x00800000;
        const DMNAMEDPIPE =      0x00200000;
        const DMSOCKET =         0x00100000;
        const DMSETUID =         0x00080000;
        const DMSETGID =         0x00040000;
        const DMACCMODE =        0o777;
        // We don't use these, but they need to exist so from_bits works properly.
        const S_IRUSR =          0o400;
        const S_IWUSR =          0o200;
        const S_IXUSR =          0o100;
        const S_IRGRP =          0o040;
        const S_IWGRP =          0o020;
        const S_IXGRP =          0o010;
        const S_IROTH =          0o004;
        const S_IWOTH =          0o002;
        const S_IXOTH =          0o001;
    }

    pub struct LinuxFileType: u32 {
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

    pub struct LinuxStatValidity: u64 {
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

    pub struct LinuxSetattrValidity: u32 {
        const MODE = 0x00000001;
        const UID = 0x00000002;
        const GID = 0x00000004;
        const SIZE = 0x00000008;
        const ATIME = 0x00000010;
        const MTIME = 0x00000020;
        const CTIME = 0x00000040;
        const ATIME_SET = 0x00000080;
        const MTIME_STE = 0x00000100;
    }
}

impl SimpleOpenMode {
    #[cfg(feature = "unix")]
    pub fn to_unix(&self) -> Option<i32> {
        let mut mode = match *self & Self::O_ACCMODE {
            Self::O_READ => libc::O_RDONLY,
            Self::O_WRITE => libc::O_WRONLY,
            Self::O_RDWR => libc::O_RDWR,
            _ => return None,
        };
        if self.contains(Self::O_TRUNC) {
            mode |= libc::O_TRUNC;
        }
        Some(mode)
    }
}

impl From<SimpleOpenMode> for fsbackend::OpenMode {
    fn from(s: SimpleOpenMode) -> fsbackend::OpenMode {
        let mut m = fsbackend::OpenMode::empty();
        m |= match s & SimpleOpenMode::O_ACCMODE {
            SimpleOpenMode::O_READ => fsbackend::OpenMode::O_RDONLY,
            SimpleOpenMode::O_WRITE => fsbackend::OpenMode::O_WRONLY,
            SimpleOpenMode::O_RDWR => fsbackend::OpenMode::O_RDWR,
            _ => fsbackend::OpenMode::O_RDONLY,
        };
        if s.contains(SimpleOpenMode::O_TRUNC) {
            m |= fsbackend::OpenMode::O_TRUNC;
        }
        m
    }
}

impl FileType {
    #[cfg(feature = "unix")]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        let ft = metadata.file_type();
        let kind = if ft.is_fifo() {
            Self::DMNAMEDPIPE
        } else if ft.is_socket() {
            Self::DMSOCKET
        } else if ft.is_block_device() || ft.is_char_device() {
            Self::DMDEVICE
        } else if ft.is_dir() {
            Self::DMDIR
        } else if ft.is_symlink() {
            Self::DMSYMLINK
        } else {
            Self::from_bits(0).unwrap()
        };
        let mut mode = Self::from_bits(metadata.mode() & 0o777).unwrap();
        if (metadata.mode() & 0o4000) != 0 {
            mode |= Self::DMSETUID;
        }
        if (metadata.mode() & 0o2000) != 0 {
            mode |= Self::DMSETGID;
        }
        kind | mode
    }

    #[cfg(feature = "unix")]
    pub fn from_unix(mode: u32) -> Self {
        let kind = match (mode as libc::mode_t) & libc::S_IFMT {
            libc::S_IFSOCK => Self::DMSOCKET,
            libc::S_IFLNK => Self::DMSYMLINK,
            libc::S_IFBLK | libc::S_IFCHR => Self::DMDEVICE,
            libc::S_IFIFO => Self::DMNAMEDPIPE,
            libc::S_IFDIR => Self::DMDIR,
            _ => Self::from_bits(0).unwrap(),
        };
        let mut dmode = Self::from_bits(mode & 0o777).unwrap();
        if (mode & 0o4000) != 0 {
            dmode |= Self::DMSETUID;
        }
        if (mode & 0o2000) != 0 {
            dmode |= Self::DMSETGID;
        }
        kind | dmode
    }
}

impl LinuxFileType {
    #[cfg(feature = "unix")]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        let ft = metadata.file_type();
        let kind = if ft.is_fifo() {
            Self::S_IFIFO
        } else if ft.is_socket() {
            Self::S_IFSOCK
        } else if ft.is_block_device() {
            Self::S_IFBLK
        } else if ft.is_char_device() {
            Self::S_IFCHR
        } else if ft.is_dir() {
            Self::S_IFDIR
        } else if ft.is_symlink() {
            Self::S_IFLNK
        } else {
            Self::from_bits(0).unwrap()
        };
        let mode = Self::from_bits(metadata.mode() & 0o7777).unwrap();
        kind | mode
    }

    #[cfg(feature = "unix")]
    pub fn from_unix(mode: u32) -> Self {
        let kind = match (mode as libc::mode_t) & libc::S_IFMT {
            libc::S_IFSOCK => Self::S_IFSOCK,
            libc::S_IFLNK => Self::S_IFLNK,
            libc::S_IFBLK => Self::S_IFBLK,
            libc::S_IFCHR => Self::S_IFCHR,
            libc::S_IFIFO => Self::S_IFIFO,
            libc::S_IFDIR => Self::S_IFDIR,
            libc::S_IFREG => Self::S_IFREG,
            _ => Self::from_bits(0).unwrap(),
        };
        let dmode = Self::from_bits(mode & 0o7777).unwrap();
        kind | dmode
    }
}

struct Deserializer<'a> {
    data: &'a [u8],
    off: AtomicUsize,
}

impl<'a> Deserializer<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            off: AtomicUsize::new(0),
        }
    }

    fn read_u8(&self) -> Result<u8, Error> {
        let off = self.off.fetch_add(1, Ordering::AcqRel);
        if off + 1 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(self.data[off])
    }

    fn read_u16(&self) -> Result<u16, Error> {
        let off = self.off.fetch_add(2, Ordering::AcqRel);
        if off + 2 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(u16::from_le_bytes(
            self.data[off..off + 2].try_into().unwrap(),
        ))
    }

    fn read_u32(&self) -> Result<u32, Error> {
        let off = self.off.fetch_add(4, Ordering::AcqRel);
        if off + 4 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(u32::from_le_bytes(
            self.data[off..off + 4].try_into().unwrap(),
        ))
    }

    fn read_u64(&self) -> Result<u64, Error> {
        let off = self.off.fetch_add(8, Ordering::AcqRel);
        if off + 8 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(u64::from_le_bytes(
            self.data[off..off + 8].try_into().unwrap(),
        ))
    }

    fn read_fid(&self) -> Result<FID, Error> {
        let off = self.off.fetch_add(4, Ordering::AcqRel);
        if off + 4 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(FID(self.data[off..off + 4].try_into().unwrap()))
    }

    fn read_qid(&self) -> Result<QID, Error> {
        let off = self.off.fetch_add(13, Ordering::AcqRel);
        if off + 13 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(QID(self.data[off..off + 13].try_into().unwrap()))
    }

    fn read_tag(&self) -> Result<Tag, Error> {
        let off = self.off.fetch_add(2, Ordering::AcqRel);
        if off + 2 > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(Tag(self.data[off..off + 2].try_into().unwrap()))
    }

    fn read_string(&self) -> Result<&[u8], Error> {
        let len = self.read_u16()? as usize;
        let off = self.off.fetch_add(len, Ordering::AcqRel);
        if off + len > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(&self.data[off..off + len])
    }

    fn read_data(&self, len: usize) -> Result<&[u8], Error> {
        let off = self.off.fetch_add(len, Ordering::AcqRel);
        if off + len > self.data.len() {
            return Err(Error::EINVAL);
        }
        Ok(&self.data[off..off + len])
    }
}

struct Serializer {
    data: Vec<u8>,
}

impl Serializer {
    fn new() -> Self {
        Self { data: Vec::new() }
    }

    fn into_inner(self) -> Vec<u8> {
        self.data
    }

    fn write_u8(&mut self, data: u8) {
        self.data.extend(&[data]);
    }

    fn write_u16(&mut self, data: u16) {
        self.data.extend(&data.to_le_bytes());
    }

    fn write_u32(&mut self, data: u32) {
        self.data.extend(&data.to_le_bytes());
    }

    fn write_u64(&mut self, data: u64) {
        self.data.extend(&data.to_le_bytes());
    }

    fn write_qid(&mut self, data: QID) {
        self.data.extend(&data.0);
    }

    fn write_string(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() > u16::MAX as usize {
            return Err(Error::ENOMEM);
        }
        self.write_u16(data.len() as u16);
        self.data.extend(data.iter());
        Ok(())
    }

    fn write_data(&mut self, data: &[u8]) {
        self.data.extend(data);
    }
}
