extern crate libc;
extern crate num_derive;
#[cfg(feature = "rustix")]
extern crate rustix;

use num_derive::FromPrimitive;
use std::borrow::Cow;
use std::fmt;
use std::io;

/// Represents a Linux error code.
///
/// These error codes are used in the 9P2000.L protocol, and we also use them in the lawn
/// protocol to provide standard error codes.  They have the meanings specified by POSIX, or by
/// Linux in case of non-POSIX codes.
#[derive(FromPrimitive, Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Error {
    EPERM = 1,
    ENOENT = 2,
    ESRCH = 3,
    EINTR = 4,
    EIO = 5,
    ENXIO = 6,
    E2BIG = 7,
    ENOEXEC = 8,
    EBADF = 9,
    ECHILD = 10,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    ENOTBLK = 15,
    EBUSY = 16,
    EEXIST = 17,
    EXDEV = 18,
    ENODEV = 19,
    ENOTDIR = 20,
    EISDIR = 21,
    EINVAL = 22,
    ENFILE = 23,
    EMFILE = 24,
    ENOTTY = 25,
    ETXTBSY = 26,
    EFBIG = 27,
    ENOSPC = 28,
    ESPIPE = 29,
    EROFS = 30,
    EMLINK = 31,
    EPIPE = 32,
    EDOM = 33,
    ERANGE = 34,
    EDEADLK = 35,
    ENAMETOOLONG = 36,
    ENOLCK = 37,
    ENOSYS = 38,
    ENOTEMPTY = 39,
    ELOOP = 40,
    ENOMSG = 42,
    EIDRM = 43,
    ECHRNG = 44,
    EL2NSYNC = 45,
    EL3HLT = 46,
    EL3RST = 47,
    ELNRNG = 48,
    EUNATCH = 49,
    ENOCSI = 50,
    EL2HLT = 51,
    EBADE = 52,
    EBADR = 53,
    EXFULL = 54,
    ENOANO = 55,
    EBADRQC = 56,
    EBADSLT = 57,
    EBFONT = 59,
    ENOSTR = 60,
    ENODATA = 61,
    ETIME = 62,
    ENOSR = 63,
    ENONET = 64,
    ENOPKG = 65,
    EREMOTE = 66,
    ENOLINK = 67,
    EADV = 68,
    ESRMNT = 69,
    ECOMM = 70,
    EPROTO = 71,
    EMULTIHOP = 72,
    EDOTDOT = 73,
    EBADMSG = 74,
    EOVERFLOW = 75,
    ENOTUNIQ = 76,
    EBADFD = 77,
    EREMCHG = 78,
    ELIBACC = 79,
    ELIBBAD = 80,
    ELIBSCN = 81,
    ELIBMAX = 82,
    ELIBEXEC = 83,
    EILSEQ = 84,
    ERESTART = 85,
    ESTRPIPE = 86,
    EUSERS = 87,
    ENOTSOCK = 88,
    EDESTADDRREQ = 89,
    EMSGSIZE = 90,
    EPROTOTYPE = 91,
    ENOPROTOOPT = 92,
    EPROTONOSUPPORT = 93,
    ESOCKTNOSUPPORT = 94,
    EOPNOTSUPP = 95,
    EPFNOSUPPORT = 96,
    EAFNOSUPPORT = 97,
    EADDRINUSE = 98,
    EADDRNOTAVAIL = 99,
    ENETDOWN = 100,
    ENETUNREACH = 101,
    ENETRESET = 102,
    ECONNABORTED = 103,
    ECONNRESET = 104,
    ENOBUFS = 105,
    EISCONN = 106,
    ENOTCONN = 107,
    ESHUTDOWN = 108,
    ETOOMANYREFS = 109,
    ETIMEDOUT = 110,
    ECONNREFUSED = 111,
    EHOSTDOWN = 112,
    EHOSTUNREACH = 113,
    EALREADY = 114,
    EINPROGRESS = 115,
    ESTALE = 116,
    EUCLEAN = 117,
    ENOTNAM = 118,
    ENAVAIL = 119,
    EISNAM = 120,
    EREMOTEIO = 121,
    EDQUOT = 122,
    ENOMEDIUM = 123,
    EMEDIUMTYPE = 124,
    ECANCELED = 125,
    ENOKEY = 126,
    EKEYEXPIRED = 127,
    EKEYREVOKED = 128,
    EKEYREJECTED = 129,
    EOWNERDEAD = 130,
    ENOTRECOVERABLE = 131,
    ERFKILL = 132,
    EHWPOISON = 133,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        let e: io::Error = (*self).into();
        write!(f, "{}", e)
    }
}

impl From<Error> for io::Error {
    #[allow(unreachable_patterns)]
    fn from(err: Error) -> io::Error {
        match err {
            Error::EPERM => io::Error::from_raw_os_error(libc::EPERM),
            Error::ENOENT => io::Error::from_raw_os_error(libc::ENOENT),
            Error::ESRCH => io::Error::from_raw_os_error(libc::ESRCH),
            Error::EINTR => io::Error::from_raw_os_error(libc::EINTR),
            Error::EIO => io::Error::from_raw_os_error(libc::EIO),
            Error::ENXIO => io::Error::from_raw_os_error(libc::ENXIO),
            Error::E2BIG => io::Error::from_raw_os_error(libc::E2BIG),
            Error::ENOEXEC => io::Error::from_raw_os_error(libc::ENOEXEC),
            Error::EBADF => io::Error::from_raw_os_error(libc::EBADF),
            Error::ECHILD => io::Error::from_raw_os_error(libc::ECHILD),
            Error::EAGAIN => io::Error::from_raw_os_error(libc::EAGAIN),
            Error::ENOMEM => io::Error::from_raw_os_error(libc::ENOMEM),
            Error::EACCES => io::Error::from_raw_os_error(libc::EACCES),
            Error::EFAULT => io::Error::from_raw_os_error(libc::EFAULT),
            Error::ENOTBLK => io::Error::from_raw_os_error(libc::ENOTBLK),
            Error::EBUSY => io::Error::from_raw_os_error(libc::EBUSY),
            Error::EEXIST => io::Error::from_raw_os_error(libc::EEXIST),
            Error::EXDEV => io::Error::from_raw_os_error(libc::EXDEV),
            Error::ENODEV => io::Error::from_raw_os_error(libc::ENODEV),
            Error::ENOTDIR => io::Error::from_raw_os_error(libc::ENOTDIR),
            Error::EISDIR => io::Error::from_raw_os_error(libc::EISDIR),
            Error::EINVAL => io::Error::from_raw_os_error(libc::EINVAL),
            Error::ENFILE => io::Error::from_raw_os_error(libc::ENFILE),
            Error::EMFILE => io::Error::from_raw_os_error(libc::EMFILE),
            Error::ENOTTY => io::Error::from_raw_os_error(libc::ENOTTY),
            Error::ETXTBSY => io::Error::from_raw_os_error(libc::ETXTBSY),
            Error::EFBIG => io::Error::from_raw_os_error(libc::EFBIG),
            Error::ENOSPC => io::Error::from_raw_os_error(libc::ENOSPC),
            Error::ESPIPE => io::Error::from_raw_os_error(libc::ESPIPE),
            Error::EROFS => io::Error::from_raw_os_error(libc::EROFS),
            Error::EMLINK => io::Error::from_raw_os_error(libc::EMLINK),
            Error::EPIPE => io::Error::from_raw_os_error(libc::EPIPE),
            Error::EDOM => io::Error::from_raw_os_error(libc::EDOM),
            Error::ERANGE => io::Error::from_raw_os_error(libc::ERANGE),
            Error::EDEADLK => io::Error::from_raw_os_error(libc::EDEADLK),
            Error::ENAMETOOLONG => io::Error::from_raw_os_error(libc::ENAMETOOLONG),
            Error::ENOLCK => io::Error::from_raw_os_error(libc::ENOLCK),
            Error::ENOSYS => io::Error::from_raw_os_error(libc::ENOSYS),
            Error::ENOTEMPTY => io::Error::from_raw_os_error(libc::ENOTEMPTY),
            Error::ELOOP => io::Error::from_raw_os_error(libc::ELOOP),
            Error::ENOMSG => io::Error::from_raw_os_error(libc::ENOMSG),
            Error::EIDRM => io::Error::from_raw_os_error(libc::EIDRM),
            #[cfg(target_os = "linux")]
            Error::ECHRNG => io::Error::from_raw_os_error(libc::ECHRNG),
            #[cfg(target_os = "linux")]
            Error::EL2NSYNC => io::Error::from_raw_os_error(libc::EL2NSYNC),
            #[cfg(target_os = "linux")]
            Error::EL3HLT => io::Error::from_raw_os_error(libc::EL3HLT),
            #[cfg(target_os = "linux")]
            Error::EL3RST => io::Error::from_raw_os_error(libc::EL3RST),
            #[cfg(target_os = "linux")]
            Error::ELNRNG => io::Error::from_raw_os_error(libc::ELNRNG),
            #[cfg(target_os = "linux")]
            Error::EUNATCH => io::Error::from_raw_os_error(libc::EUNATCH),
            #[cfg(target_os = "linux")]
            Error::ENOCSI => io::Error::from_raw_os_error(libc::ENOCSI),
            #[cfg(target_os = "linux")]
            Error::EL2HLT => io::Error::from_raw_os_error(libc::EL2HLT),
            #[cfg(target_os = "linux")]
            Error::EBADE => io::Error::from_raw_os_error(libc::EBADE),
            #[cfg(target_os = "linux")]
            Error::EBADR => io::Error::from_raw_os_error(libc::EBADR),
            #[cfg(target_os = "linux")]
            Error::EXFULL => io::Error::from_raw_os_error(libc::EXFULL),
            #[cfg(target_os = "linux")]
            Error::ENOANO => io::Error::from_raw_os_error(libc::ENOANO),
            #[cfg(target_os = "linux")]
            Error::EBADRQC => io::Error::from_raw_os_error(libc::EBADRQC),
            #[cfg(target_os = "linux")]
            Error::EBADSLT => io::Error::from_raw_os_error(libc::EBADSLT),
            #[cfg(target_os = "linux")]
            Error::EBFONT => io::Error::from_raw_os_error(libc::EBFONT),
            #[cfg(target_os = "linux")]
            Error::ENOSTR => io::Error::from_raw_os_error(libc::ENOSTR),
            #[cfg(target_os = "linux")]
            Error::ENODATA => io::Error::from_raw_os_error(libc::ENODATA),
            #[cfg(target_os = "linux")]
            Error::ETIME => io::Error::from_raw_os_error(libc::ETIME),
            #[cfg(target_os = "linux")]
            Error::ENOSR => io::Error::from_raw_os_error(libc::ENOSR),
            #[cfg(target_os = "linux")]
            Error::ENONET => io::Error::from_raw_os_error(libc::ENONET),
            #[cfg(target_os = "linux")]
            Error::ENOPKG => io::Error::from_raw_os_error(libc::ENOPKG),
            Error::EREMOTE => io::Error::from_raw_os_error(libc::EREMOTE),
            Error::ENOLINK => io::Error::from_raw_os_error(libc::ENOLINK),
            #[cfg(target_os = "linux")]
            Error::EADV => io::Error::from_raw_os_error(libc::EADV),
            #[cfg(target_os = "linux")]
            Error::ESRMNT => io::Error::from_raw_os_error(libc::ESRMNT),
            #[cfg(target_os = "linux")]
            Error::ECOMM => io::Error::from_raw_os_error(libc::ECOMM),
            Error::EPROTO => io::Error::from_raw_os_error(libc::EPROTO),
            Error::EMULTIHOP => io::Error::from_raw_os_error(libc::EMULTIHOP),
            #[cfg(target_os = "linux")]
            Error::EDOTDOT => io::Error::from_raw_os_error(libc::EDOTDOT),
            Error::EBADMSG => io::Error::from_raw_os_error(libc::EBADMSG),
            Error::EOVERFLOW => io::Error::from_raw_os_error(libc::EOVERFLOW),
            #[cfg(target_os = "linux")]
            Error::ENOTUNIQ => io::Error::from_raw_os_error(libc::ENOTUNIQ),
            #[cfg(target_os = "linux")]
            Error::EBADFD => io::Error::from_raw_os_error(libc::EBADFD),
            #[cfg(target_os = "linux")]
            Error::EREMCHG => io::Error::from_raw_os_error(libc::EREMCHG),
            #[cfg(target_os = "linux")]
            Error::ELIBACC => io::Error::from_raw_os_error(libc::ELIBACC),
            #[cfg(target_os = "linux")]
            Error::ELIBBAD => io::Error::from_raw_os_error(libc::ELIBBAD),
            #[cfg(target_os = "linux")]
            Error::ELIBSCN => io::Error::from_raw_os_error(libc::ELIBSCN),
            #[cfg(target_os = "linux")]
            Error::ELIBMAX => io::Error::from_raw_os_error(libc::ELIBMAX),
            #[cfg(target_os = "linux")]
            Error::ELIBEXEC => io::Error::from_raw_os_error(libc::ELIBEXEC),
            Error::EILSEQ => io::Error::from_raw_os_error(libc::EILSEQ),
            #[cfg(target_os = "linux")]
            Error::ERESTART => io::Error::from_raw_os_error(libc::ERESTART),
            #[cfg(target_os = "linux")]
            Error::ESTRPIPE => io::Error::from_raw_os_error(libc::ESTRPIPE),
            Error::EUSERS => io::Error::from_raw_os_error(libc::EUSERS),
            Error::ENOTSOCK => io::Error::from_raw_os_error(libc::ENOTSOCK),
            Error::EDESTADDRREQ => io::Error::from_raw_os_error(libc::EDESTADDRREQ),
            Error::EMSGSIZE => io::Error::from_raw_os_error(libc::EMSGSIZE),
            Error::EPROTOTYPE => io::Error::from_raw_os_error(libc::EPROTOTYPE),
            Error::ENOPROTOOPT => io::Error::from_raw_os_error(libc::ENOPROTOOPT),
            Error::EPROTONOSUPPORT => io::Error::from_raw_os_error(libc::EPROTONOSUPPORT),
            Error::ESOCKTNOSUPPORT => io::Error::from_raw_os_error(libc::ESOCKTNOSUPPORT),
            Error::EOPNOTSUPP => io::Error::from_raw_os_error(libc::EOPNOTSUPP),
            Error::EPFNOSUPPORT => io::Error::from_raw_os_error(libc::EPFNOSUPPORT),
            Error::EAFNOSUPPORT => io::Error::from_raw_os_error(libc::EAFNOSUPPORT),
            Error::EADDRINUSE => io::Error::from_raw_os_error(libc::EADDRINUSE),
            Error::EADDRNOTAVAIL => io::Error::from_raw_os_error(libc::EADDRNOTAVAIL),
            Error::ENETDOWN => io::Error::from_raw_os_error(libc::ENETDOWN),
            Error::ENETUNREACH => io::Error::from_raw_os_error(libc::ENETUNREACH),
            Error::ENETRESET => io::Error::from_raw_os_error(libc::ENETRESET),
            Error::ECONNABORTED => io::Error::from_raw_os_error(libc::ECONNABORTED),
            Error::ECONNRESET => io::Error::from_raw_os_error(libc::ECONNRESET),
            Error::ENOBUFS => io::Error::from_raw_os_error(libc::ENOBUFS),
            Error::EISCONN => io::Error::from_raw_os_error(libc::EISCONN),
            Error::ENOTCONN => io::Error::from_raw_os_error(libc::ENOTCONN),
            Error::ESHUTDOWN => io::Error::from_raw_os_error(libc::ESHUTDOWN),
            Error::ETOOMANYREFS => io::Error::from_raw_os_error(libc::ETOOMANYREFS),
            Error::ETIMEDOUT => io::Error::from_raw_os_error(libc::ETIMEDOUT),
            Error::ECONNREFUSED => io::Error::from_raw_os_error(libc::ECONNREFUSED),
            Error::EHOSTDOWN => io::Error::from_raw_os_error(libc::EHOSTDOWN),
            Error::EHOSTUNREACH => io::Error::from_raw_os_error(libc::EHOSTUNREACH),
            Error::EALREADY => io::Error::from_raw_os_error(libc::EALREADY),
            Error::EINPROGRESS => io::Error::from_raw_os_error(libc::EINPROGRESS),
            Error::ESTALE => io::Error::from_raw_os_error(libc::ESTALE),
            #[cfg(target_os = "linux")]
            Error::EUCLEAN => io::Error::from_raw_os_error(libc::EUCLEAN),
            #[cfg(target_os = "linux")]
            Error::ENOTNAM => io::Error::from_raw_os_error(libc::ENOTNAM),
            #[cfg(target_os = "linux")]
            Error::ENAVAIL => io::Error::from_raw_os_error(libc::ENAVAIL),
            #[cfg(target_os = "linux")]
            Error::EISNAM => io::Error::from_raw_os_error(libc::EISNAM),
            #[cfg(target_os = "linux")]
            Error::EREMOTEIO => io::Error::from_raw_os_error(libc::EREMOTEIO),
            Error::EDQUOT => io::Error::from_raw_os_error(libc::EDQUOT),
            #[cfg(target_os = "linux")]
            Error::ENOMEDIUM => io::Error::from_raw_os_error(libc::ENOMEDIUM),
            #[cfg(target_os = "linux")]
            Error::EMEDIUMTYPE => io::Error::from_raw_os_error(libc::EMEDIUMTYPE),
            Error::ECANCELED => io::Error::from_raw_os_error(libc::ECANCELED),
            #[cfg(target_os = "linux")]
            Error::ENOKEY => io::Error::from_raw_os_error(libc::ENOKEY),
            #[cfg(target_os = "linux")]
            Error::EKEYEXPIRED => io::Error::from_raw_os_error(libc::EKEYEXPIRED),
            #[cfg(target_os = "linux")]
            Error::EKEYREVOKED => io::Error::from_raw_os_error(libc::EKEYREVOKED),
            #[cfg(target_os = "linux")]
            Error::EKEYREJECTED => io::Error::from_raw_os_error(libc::EKEYREJECTED),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Error::EOWNERDEAD => io::Error::from_raw_os_error(libc::EOWNERDEAD),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Error::ENOTRECOVERABLE => io::Error::from_raw_os_error(libc::ENOTRECOVERABLE),
            #[cfg(target_os = "linux")]
            Error::ERFKILL => io::Error::from_raw_os_error(libc::ERFKILL),
            #[cfg(target_os = "linux")]
            Error::EHWPOISON => io::Error::from_raw_os_error(libc::EHWPOISON),
            _ => io::Error::from_raw_os_error(libc::EINVAL),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::from(&err)
    }
}

impl<'a> From<&'a mut io::Error> for Error {
    fn from(err: &'a mut io::Error) -> Error {
        Error::from(&*err)
    }
}

impl<'a> From<&'a io::Error> for Error {
    // Some OSes, like Linux, are missing separate values for some errors and we don't want a
    // warning here.
    #[allow(unreachable_patterns)]
    fn from(err: &'a io::Error) -> Error {
        match err.raw_os_error() {
            Some(libc::EPERM) => Self::EPERM,
            Some(libc::ENOENT) => Self::ENOENT,
            Some(libc::ESRCH) => Self::ESRCH,
            Some(libc::EINTR) => Self::EINTR,
            Some(libc::EIO) => Self::EIO,
            Some(libc::ENXIO) => Self::ENXIO,
            Some(libc::E2BIG) => Self::E2BIG,
            Some(libc::ENOEXEC) => Self::ENOEXEC,
            Some(libc::EBADF) => Self::EBADF,
            Some(libc::ECHILD) => Self::ECHILD,
            Some(libc::EAGAIN) => Self::EAGAIN,
            Some(libc::ENOMEM) => Self::ENOMEM,
            Some(libc::EACCES) => Self::EACCES,
            Some(libc::EFAULT) => Self::EFAULT,
            Some(libc::ENOTBLK) => Self::ENOTBLK,
            Some(libc::EBUSY) => Self::EBUSY,
            Some(libc::EEXIST) => Self::EEXIST,
            Some(libc::EXDEV) => Self::EXDEV,
            Some(libc::ENODEV) => Self::ENODEV,
            Some(libc::ENOTDIR) => Self::ENOTDIR,
            Some(libc::EISDIR) => Self::EISDIR,
            Some(libc::EINVAL) => Self::EINVAL,
            Some(libc::ENFILE) => Self::ENFILE,
            Some(libc::EMFILE) => Self::EMFILE,
            Some(libc::ENOTTY) => Self::ENOTTY,
            Some(libc::ETXTBSY) => Self::ETXTBSY,
            Some(libc::EFBIG) => Self::EFBIG,
            Some(libc::ENOSPC) => Self::ENOSPC,
            Some(libc::ESPIPE) => Self::ESPIPE,
            Some(libc::EROFS) => Self::EROFS,
            Some(libc::EMLINK) => Self::EMLINK,
            Some(libc::EPIPE) => Self::EPIPE,
            Some(libc::EDOM) => Self::EDOM,
            Some(libc::ERANGE) => Self::ERANGE,
            Some(libc::EDEADLK) => Self::EDEADLK,
            Some(libc::ENAMETOOLONG) => Self::ENAMETOOLONG,
            Some(libc::ENOLCK) => Self::ENOLCK,
            Some(libc::ENOSYS) => Self::ENOSYS,
            Some(libc::ENOTEMPTY) => Self::ENOTEMPTY,
            Some(libc::ELOOP) => Self::ELOOP,
            Some(libc::ENOMSG) => Self::ENOMSG,
            Some(libc::EIDRM) => Self::EIDRM,
            #[cfg(target_os = "linux")]
            Some(libc::ECHRNG) => Self::ECHRNG,
            #[cfg(target_os = "linux")]
            Some(libc::EL2NSYNC) => Self::EL2NSYNC,
            #[cfg(target_os = "linux")]
            Some(libc::EL3HLT) => Self::EL3HLT,
            #[cfg(target_os = "linux")]
            Some(libc::EL3RST) => Self::EL3RST,
            #[cfg(target_os = "linux")]
            Some(libc::ELNRNG) => Self::ELNRNG,
            #[cfg(target_os = "linux")]
            Some(libc::EUNATCH) => Self::EUNATCH,
            #[cfg(target_os = "linux")]
            Some(libc::ENOCSI) => Self::ENOCSI,
            #[cfg(target_os = "linux")]
            Some(libc::EL2HLT) => Self::EL2HLT,
            #[cfg(target_os = "linux")]
            Some(libc::EBADE) => Self::EBADE,
            #[cfg(target_os = "linux")]
            Some(libc::EBADR) => Self::EBADR,
            #[cfg(target_os = "linux")]
            Some(libc::EXFULL) => Self::EXFULL,
            #[cfg(target_os = "linux")]
            Some(libc::ENOANO) => Self::ENOANO,
            #[cfg(target_os = "linux")]
            Some(libc::EBADRQC) => Self::EBADRQC,
            #[cfg(target_os = "linux")]
            Some(libc::EBADSLT) => Self::EBADSLT,
            #[cfg(target_os = "linux")]
            Some(libc::EBFONT) => Self::EBFONT,
            #[cfg(target_os = "linux")]
            Some(libc::ENOSTR) => Self::ENOSTR,
            #[cfg(target_os = "linux")]
            Some(libc::ENODATA) => Self::ENODATA,
            #[cfg(target_os = "linux")]
            Some(libc::ETIME) => Self::ETIME,
            #[cfg(target_os = "linux")]
            Some(libc::ENOSR) => Self::ENOSR,
            #[cfg(target_os = "linux")]
            Some(libc::ENONET) => Self::ENONET,
            #[cfg(target_os = "linux")]
            Some(libc::ENOPKG) => Self::ENOPKG,
            Some(libc::EREMOTE) => Self::EREMOTE,
            Some(libc::ENOLINK) => Self::ENOLINK,
            #[cfg(target_os = "linux")]
            Some(libc::EADV) => Self::EADV,
            #[cfg(target_os = "linux")]
            Some(libc::ESRMNT) => Self::ESRMNT,
            #[cfg(target_os = "linux")]
            Some(libc::ECOMM) => Self::ECOMM,
            Some(libc::EPROTO) => Self::EPROTO,
            Some(libc::EMULTIHOP) => Self::EMULTIHOP,
            #[cfg(target_os = "linux")]
            Some(libc::EDOTDOT) => Self::EDOTDOT,
            Some(libc::EBADMSG) => Self::EBADMSG,
            Some(libc::EOVERFLOW) => Self::EOVERFLOW,
            #[cfg(target_os = "linux")]
            Some(libc::ENOTUNIQ) => Self::ENOTUNIQ,
            #[cfg(target_os = "linux")]
            Some(libc::EBADFD) => Self::EBADFD,
            #[cfg(target_os = "linux")]
            Some(libc::EREMCHG) => Self::EREMCHG,
            #[cfg(target_os = "linux")]
            Some(libc::ELIBACC) => Self::ELIBACC,
            #[cfg(target_os = "linux")]
            Some(libc::ELIBBAD) => Self::ELIBBAD,
            #[cfg(target_os = "linux")]
            Some(libc::ELIBSCN) => Self::ELIBSCN,
            #[cfg(target_os = "linux")]
            Some(libc::ELIBMAX) => Self::ELIBMAX,
            #[cfg(target_os = "linux")]
            Some(libc::ELIBEXEC) => Self::ELIBEXEC,
            Some(libc::EILSEQ) => Self::EILSEQ,
            #[cfg(target_os = "linux")]
            Some(libc::ERESTART) => Self::ERESTART,
            #[cfg(target_os = "linux")]
            Some(libc::ESTRPIPE) => Self::ESTRPIPE,
            Some(libc::EUSERS) => Self::EUSERS,
            Some(libc::ENOTSOCK) => Self::ENOTSOCK,
            Some(libc::EDESTADDRREQ) => Self::EDESTADDRREQ,
            Some(libc::EMSGSIZE) => Self::EMSGSIZE,
            Some(libc::EPROTOTYPE) => Self::EPROTOTYPE,
            Some(libc::ENOPROTOOPT) => Self::ENOPROTOOPT,
            Some(libc::EPROTONOSUPPORT) => Self::EPROTONOSUPPORT,
            Some(libc::ESOCKTNOSUPPORT) => Self::ESOCKTNOSUPPORT,
            Some(libc::EOPNOTSUPP) => Self::EOPNOTSUPP,
            Some(libc::EPFNOSUPPORT) => Self::EPFNOSUPPORT,
            Some(libc::EAFNOSUPPORT) => Self::EAFNOSUPPORT,
            Some(libc::EADDRINUSE) => Self::EADDRINUSE,
            Some(libc::EADDRNOTAVAIL) => Self::EADDRNOTAVAIL,
            Some(libc::ENETDOWN) => Self::ENETDOWN,
            Some(libc::ENETUNREACH) => Self::ENETUNREACH,
            Some(libc::ENETRESET) => Self::ENETRESET,
            Some(libc::ECONNABORTED) => Self::ECONNABORTED,
            Some(libc::ECONNRESET) => Self::ECONNRESET,
            Some(libc::ENOBUFS) => Self::ENOBUFS,
            Some(libc::EISCONN) => Self::EISCONN,
            Some(libc::ENOTCONN) => Self::ENOTCONN,
            Some(libc::ESHUTDOWN) => Self::ESHUTDOWN,
            Some(libc::ETOOMANYREFS) => Self::ETOOMANYREFS,
            Some(libc::ETIMEDOUT) => Self::ETIMEDOUT,
            Some(libc::ECONNREFUSED) => Self::ECONNREFUSED,
            Some(libc::EHOSTDOWN) => Self::EHOSTDOWN,
            Some(libc::EHOSTUNREACH) => Self::EHOSTUNREACH,
            Some(libc::EALREADY) => Self::EALREADY,
            Some(libc::EINPROGRESS) => Self::EINPROGRESS,
            Some(libc::ESTALE) => Self::ESTALE,
            #[cfg(target_os = "linux")]
            Some(libc::EUCLEAN) => Self::EUCLEAN,
            #[cfg(target_os = "linux")]
            Some(libc::ENOTNAM) => Self::ENOTNAM,
            #[cfg(target_os = "linux")]
            Some(libc::ENAVAIL) => Self::ENAVAIL,
            #[cfg(target_os = "linux")]
            Some(libc::EISNAM) => Self::EISNAM,
            #[cfg(target_os = "linux")]
            Some(libc::EREMOTEIO) => Self::EREMOTEIO,
            Some(libc::EDQUOT) => Self::EDQUOT,
            #[cfg(target_os = "linux")]
            Some(libc::ENOMEDIUM) => Self::ENOMEDIUM,
            #[cfg(target_os = "linux")]
            Some(libc::EMEDIUMTYPE) => Self::EMEDIUMTYPE,
            Some(libc::ECANCELED) => Self::ECANCELED,
            #[cfg(target_os = "linux")]
            Some(libc::ENOKEY) => Self::ENOKEY,
            #[cfg(target_os = "linux")]
            Some(libc::EKEYEXPIRED) => Self::EKEYEXPIRED,
            #[cfg(target_os = "linux")]
            Some(libc::EKEYREVOKED) => Self::EKEYREVOKED,
            #[cfg(target_os = "linux")]
            Some(libc::EKEYREJECTED) => Self::EKEYREJECTED,
            // These are present on neither NetBSD nor macOS.
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Some(libc::EOWNERDEAD) => Self::EOWNERDEAD,
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            Some(libc::ENOTRECOVERABLE) => Self::ENOTRECOVERABLE,
            #[cfg(target_os = "linux")]
            Some(libc::ERFKILL) => Self::ERFKILL,
            #[cfg(target_os = "linux")]
            Some(libc::EHWPOISON) => Self::EHWPOISON,

            Some(libc::EWOULDBLOCK) => Self::EAGAIN,
            Some(libc::ENOTSUP) => Self::EOPNOTSUPP,
            #[cfg(target_os = "linux")]
            Some(libc::EDEADLOCK) => Self::EDEADLK,
            #[cfg(target_os = "netbsd")]
            Some(libc::EFTYPE) => Self::ELOOP,
            Some(_) | None => Self::EINVAL,
        }
    }
}

#[cfg(feature = "rustix")]
impl From<Error> for rustix::io::Errno {
    #[allow(unreachable_patterns)]
    fn from(err: Error) -> rustix::io::Errno {
        match err {
            Error::EPERM => rustix::io::Errno::PERM,
            Error::ENOENT => rustix::io::Errno::NOENT,
            Error::ESRCH => rustix::io::Errno::SRCH,
            Error::EINTR => rustix::io::Errno::INTR,
            Error::EIO => rustix::io::Errno::IO,
            Error::ENXIO => rustix::io::Errno::NXIO,
            Error::E2BIG => rustix::io::Errno::TOOBIG,
            Error::ENOEXEC => rustix::io::Errno::NOEXEC,
            Error::EBADF => rustix::io::Errno::BADF,
            Error::ECHILD => rustix::io::Errno::CHILD,
            Error::EAGAIN => rustix::io::Errno::AGAIN,
            Error::ENOMEM => rustix::io::Errno::NOMEM,
            Error::EACCES => rustix::io::Errno::ACCESS,
            Error::EFAULT => rustix::io::Errno::FAULT,
            Error::ENOTBLK => rustix::io::Errno::NOTBLK,
            Error::EBUSY => rustix::io::Errno::BUSY,
            Error::EEXIST => rustix::io::Errno::EXIST,
            Error::EXDEV => rustix::io::Errno::XDEV,
            Error::ENODEV => rustix::io::Errno::NODEV,
            Error::ENOTDIR => rustix::io::Errno::NOTDIR,
            Error::EISDIR => rustix::io::Errno::ISDIR,
            Error::EINVAL => rustix::io::Errno::INVAL,
            Error::ENFILE => rustix::io::Errno::NFILE,
            Error::EMFILE => rustix::io::Errno::MFILE,
            Error::ENOTTY => rustix::io::Errno::NOTTY,
            Error::ETXTBSY => rustix::io::Errno::TXTBSY,
            Error::EFBIG => rustix::io::Errno::FBIG,
            Error::ENOSPC => rustix::io::Errno::NOSPC,
            Error::ESPIPE => rustix::io::Errno::SPIPE,
            Error::EROFS => rustix::io::Errno::ROFS,
            Error::EMLINK => rustix::io::Errno::MLINK,
            Error::EPIPE => rustix::io::Errno::PIPE,
            Error::EDOM => rustix::io::Errno::DOM,
            Error::ERANGE => rustix::io::Errno::RANGE,
            Error::EDEADLK => rustix::io::Errno::DEADLK,
            Error::ENAMETOOLONG => rustix::io::Errno::NAMETOOLONG,
            Error::ENOLCK => rustix::io::Errno::NOLCK,
            Error::ENOSYS => rustix::io::Errno::NOSYS,
            Error::ENOTEMPTY => rustix::io::Errno::NOTEMPTY,
            Error::ELOOP => rustix::io::Errno::LOOP,
            Error::ENOMSG => rustix::io::Errno::NOMSG,
            Error::EIDRM => rustix::io::Errno::IDRM,
            #[cfg(target_os = "linux")]
            Error::ECHRNG => rustix::io::Errno::CHRNG,
            #[cfg(target_os = "linux")]
            Error::EL2NSYNC => rustix::io::Errno::L2NSYNC,
            #[cfg(target_os = "linux")]
            Error::EL3HLT => rustix::io::Errno::L3HLT,
            #[cfg(target_os = "linux")]
            Error::EL3RST => rustix::io::Errno::L3RST,
            #[cfg(target_os = "linux")]
            Error::ELNRNG => rustix::io::Errno::LNRNG,
            #[cfg(target_os = "linux")]
            Error::EUNATCH => rustix::io::Errno::UNATCH,
            #[cfg(target_os = "linux")]
            Error::ENOCSI => rustix::io::Errno::NOCSI,
            #[cfg(target_os = "linux")]
            Error::EL2HLT => rustix::io::Errno::L2HLT,
            #[cfg(target_os = "linux")]
            Error::EBADE => rustix::io::Errno::BADE,
            #[cfg(target_os = "linux")]
            Error::EBADR => rustix::io::Errno::BADR,
            #[cfg(target_os = "linux")]
            Error::EXFULL => rustix::io::Errno::XFULL,
            #[cfg(target_os = "linux")]
            Error::ENOANO => rustix::io::Errno::NOANO,
            #[cfg(target_os = "linux")]
            Error::EBADRQC => rustix::io::Errno::BADRQC,
            #[cfg(target_os = "linux")]
            Error::EBADSLT => rustix::io::Errno::BADSLT,
            #[cfg(target_os = "linux")]
            Error::EBFONT => rustix::io::Errno::BFONT,
            #[cfg(target_os = "linux")]
            Error::ENOSTR => rustix::io::Errno::NOSTR,
            #[cfg(target_os = "linux")]
            Error::ENODATA => rustix::io::Errno::NODATA,
            #[cfg(target_os = "linux")]
            Error::ETIME => rustix::io::Errno::TIME,
            #[cfg(target_os = "linux")]
            Error::ENOSR => rustix::io::Errno::NOSR,
            #[cfg(target_os = "linux")]
            Error::ENONET => rustix::io::Errno::NONET,
            #[cfg(target_os = "linux")]
            Error::ENOPKG => rustix::io::Errno::NOPKG,
            Error::EREMOTE => rustix::io::Errno::REMOTE,
            Error::ENOLINK => rustix::io::Errno::NOLINK,
            #[cfg(target_os = "linux")]
            Error::EADV => rustix::io::Errno::ADV,
            #[cfg(target_os = "linux")]
            Error::ESRMNT => rustix::io::Errno::SRMNT,
            #[cfg(target_os = "linux")]
            Error::ECOMM => rustix::io::Errno::COMM,
            Error::EPROTO => rustix::io::Errno::PROTO,
            Error::EMULTIHOP => rustix::io::Errno::MULTIHOP,
            #[cfg(target_os = "linux")]
            Error::EDOTDOT => rustix::io::Errno::DOTDOT,
            Error::EBADMSG => rustix::io::Errno::BADMSG,
            Error::EOVERFLOW => rustix::io::Errno::OVERFLOW,
            #[cfg(target_os = "linux")]
            Error::ENOTUNIQ => rustix::io::Errno::NOTUNIQ,
            #[cfg(target_os = "linux")]
            Error::EBADFD => rustix::io::Errno::BADFD,
            #[cfg(target_os = "linux")]
            Error::EREMCHG => rustix::io::Errno::REMCHG,
            #[cfg(target_os = "linux")]
            Error::ELIBACC => rustix::io::Errno::LIBACC,
            #[cfg(target_os = "linux")]
            Error::ELIBBAD => rustix::io::Errno::LIBBAD,
            #[cfg(target_os = "linux")]
            Error::ELIBSCN => rustix::io::Errno::LIBSCN,
            #[cfg(target_os = "linux")]
            Error::ELIBMAX => rustix::io::Errno::LIBMAX,
            #[cfg(target_os = "linux")]
            Error::ELIBEXEC => rustix::io::Errno::LIBEXEC,
            Error::EILSEQ => rustix::io::Errno::ILSEQ,
            #[cfg(target_os = "linux")]
            Error::ERESTART => rustix::io::Errno::RESTART,
            #[cfg(target_os = "linux")]
            Error::ESTRPIPE => rustix::io::Errno::STRPIPE,
            Error::EUSERS => rustix::io::Errno::USERS,
            Error::ENOTSOCK => rustix::io::Errno::NOTSOCK,
            Error::EDESTADDRREQ => rustix::io::Errno::DESTADDRREQ,
            Error::EMSGSIZE => rustix::io::Errno::MSGSIZE,
            Error::EPROTOTYPE => rustix::io::Errno::PROTOTYPE,
            Error::ENOPROTOOPT => rustix::io::Errno::NOPROTOOPT,
            Error::EPROTONOSUPPORT => rustix::io::Errno::PROTONOSUPPORT,
            Error::ESOCKTNOSUPPORT => rustix::io::Errno::SOCKTNOSUPPORT,
            Error::EOPNOTSUPP => rustix::io::Errno::OPNOTSUPP,
            Error::EPFNOSUPPORT => rustix::io::Errno::PFNOSUPPORT,
            Error::EAFNOSUPPORT => rustix::io::Errno::AFNOSUPPORT,
            Error::EADDRINUSE => rustix::io::Errno::ADDRINUSE,
            Error::EADDRNOTAVAIL => rustix::io::Errno::ADDRNOTAVAIL,
            Error::ENETDOWN => rustix::io::Errno::NETDOWN,
            Error::ENETUNREACH => rustix::io::Errno::NETUNREACH,
            Error::ENETRESET => rustix::io::Errno::NETRESET,
            Error::ECONNABORTED => rustix::io::Errno::CONNABORTED,
            Error::ECONNRESET => rustix::io::Errno::CONNRESET,
            Error::ENOBUFS => rustix::io::Errno::NOBUFS,
            Error::EISCONN => rustix::io::Errno::ISCONN,
            Error::ENOTCONN => rustix::io::Errno::NOTCONN,
            Error::ESHUTDOWN => rustix::io::Errno::SHUTDOWN,
            Error::ETOOMANYREFS => rustix::io::Errno::TOOMANYREFS,
            Error::ETIMEDOUT => rustix::io::Errno::TIMEDOUT,
            Error::ECONNREFUSED => rustix::io::Errno::CONNREFUSED,
            Error::EHOSTDOWN => rustix::io::Errno::HOSTDOWN,
            Error::EHOSTUNREACH => rustix::io::Errno::HOSTUNREACH,
            Error::EALREADY => rustix::io::Errno::ALREADY,
            Error::EINPROGRESS => rustix::io::Errno::INPROGRESS,
            Error::ESTALE => rustix::io::Errno::STALE,
            #[cfg(target_os = "linux")]
            Error::EUCLEAN => rustix::io::Errno::UCLEAN,
            #[cfg(target_os = "linux")]
            Error::ENOTNAM => rustix::io::Errno::NOTNAM,
            #[cfg(target_os = "linux")]
            Error::ENAVAIL => rustix::io::Errno::NAVAIL,
            #[cfg(target_os = "linux")]
            Error::EISNAM => rustix::io::Errno::ISNAM,
            #[cfg(target_os = "linux")]
            Error::EREMOTEIO => rustix::io::Errno::REMOTEIO,
            Error::EDQUOT => rustix::io::Errno::DQUOT,
            #[cfg(target_os = "linux")]
            Error::ENOMEDIUM => rustix::io::Errno::NOMEDIUM,
            #[cfg(target_os = "linux")]
            Error::EMEDIUMTYPE => rustix::io::Errno::MEDIUMTYPE,
            Error::ECANCELED => rustix::io::Errno::CANCELED,
            #[cfg(target_os = "linux")]
            Error::ENOKEY => rustix::io::Errno::NOKEY,
            #[cfg(target_os = "linux")]
            Error::EKEYEXPIRED => rustix::io::Errno::KEYEXPIRED,
            #[cfg(target_os = "linux")]
            Error::EKEYREVOKED => rustix::io::Errno::KEYREVOKED,
            #[cfg(target_os = "linux")]
            Error::EKEYREJECTED => rustix::io::Errno::KEYREJECTED,
            #[cfg(target_os = "linux")]
            Error::EOWNERDEAD => rustix::io::Errno::OWNERDEAD,
            #[cfg(target_os = "linux")]
            Error::ENOTRECOVERABLE => rustix::io::Errno::NOTRECOVERABLE,
            #[cfg(target_os = "linux")]
            Error::ERFKILL => rustix::io::Errno::RFKILL,
            #[cfg(target_os = "linux")]
            Error::EHWPOISON => rustix::io::Errno::HWPOISON,
            _ => rustix::io::Errno::INVAL,
        }
    }
}

#[cfg(feature = "rustix")]
impl From<rustix::io::Errno> for Error {
    // Some OSes, like Linux, are missing separate values for some errors and we don't want a
    // warning here.
    #[allow(unreachable_patterns)]
    fn from(err: rustix::io::Errno) -> Error {
        match err {
            rustix::io::Errno::PERM => Self::EPERM,
            rustix::io::Errno::NOENT => Self::ENOENT,
            rustix::io::Errno::SRCH => Self::ESRCH,
            rustix::io::Errno::INTR => Self::EINTR,
            rustix::io::Errno::IO => Self::EIO,
            rustix::io::Errno::NXIO => Self::ENXIO,
            rustix::io::Errno::TOOBIG => Self::E2BIG,
            rustix::io::Errno::NOEXEC => Self::ENOEXEC,
            rustix::io::Errno::BADF => Self::EBADF,
            rustix::io::Errno::CHILD => Self::ECHILD,
            rustix::io::Errno::AGAIN => Self::EAGAIN,
            rustix::io::Errno::NOMEM => Self::ENOMEM,
            rustix::io::Errno::ACCESS => Self::EACCES,
            rustix::io::Errno::FAULT => Self::EFAULT,
            rustix::io::Errno::NOTBLK => Self::ENOTBLK,
            rustix::io::Errno::BUSY => Self::EBUSY,
            rustix::io::Errno::EXIST => Self::EEXIST,
            rustix::io::Errno::XDEV => Self::EXDEV,
            rustix::io::Errno::NODEV => Self::ENODEV,
            rustix::io::Errno::NOTDIR => Self::ENOTDIR,
            rustix::io::Errno::ISDIR => Self::EISDIR,
            rustix::io::Errno::INVAL => Self::EINVAL,
            rustix::io::Errno::NFILE => Self::ENFILE,
            rustix::io::Errno::MFILE => Self::EMFILE,
            rustix::io::Errno::NOTTY => Self::ENOTTY,
            rustix::io::Errno::TXTBSY => Self::ETXTBSY,
            rustix::io::Errno::FBIG => Self::EFBIG,
            rustix::io::Errno::NOSPC => Self::ENOSPC,
            rustix::io::Errno::SPIPE => Self::ESPIPE,
            rustix::io::Errno::ROFS => Self::EROFS,
            rustix::io::Errno::MLINK => Self::EMLINK,
            rustix::io::Errno::PIPE => Self::EPIPE,
            rustix::io::Errno::DOM => Self::EDOM,
            rustix::io::Errno::RANGE => Self::ERANGE,
            rustix::io::Errno::DEADLK => Self::EDEADLK,
            rustix::io::Errno::NAMETOOLONG => Self::ENAMETOOLONG,
            rustix::io::Errno::NOLCK => Self::ENOLCK,
            rustix::io::Errno::NOSYS => Self::ENOSYS,
            rustix::io::Errno::NOTEMPTY => Self::ENOTEMPTY,
            rustix::io::Errno::LOOP => Self::ELOOP,
            rustix::io::Errno::NOMSG => Self::ENOMSG,
            rustix::io::Errno::IDRM => Self::EIDRM,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::CHRNG => Self::ECHRNG,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::L2NSYNC => Self::EL2NSYNC,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::L3HLT => Self::EL3HLT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::L3RST => Self::EL3RST,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LNRNG => Self::ELNRNG,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::UNATCH => Self::EUNATCH,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOCSI => Self::ENOCSI,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::L2HLT => Self::EL2HLT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BADE => Self::EBADE,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BADR => Self::EBADR,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::XFULL => Self::EXFULL,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOANO => Self::ENOANO,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BADRQC => Self::EBADRQC,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BADSLT => Self::EBADSLT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BFONT => Self::EBFONT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOSTR => Self::ENOSTR,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NODATA => Self::ENODATA,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::TIME => Self::ETIME,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOSR => Self::ENOSR,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NONET => Self::ENONET,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOPKG => Self::ENOPKG,
            rustix::io::Errno::REMOTE => Self::EREMOTE,
            rustix::io::Errno::NOLINK => Self::ENOLINK,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::ADV => Self::EADV,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::SRMNT => Self::ESRMNT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::COMM => Self::ECOMM,
            rustix::io::Errno::PROTO => Self::EPROTO,
            rustix::io::Errno::MULTIHOP => Self::EMULTIHOP,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::DOTDOT => Self::EDOTDOT,
            rustix::io::Errno::BADMSG => Self::EBADMSG,
            rustix::io::Errno::OVERFLOW => Self::EOVERFLOW,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOTUNIQ => Self::ENOTUNIQ,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::BADFD => Self::EBADFD,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::REMCHG => Self::EREMCHG,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LIBACC => Self::ELIBACC,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LIBBAD => Self::ELIBBAD,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LIBSCN => Self::ELIBSCN,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LIBMAX => Self::ELIBMAX,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::LIBEXEC => Self::ELIBEXEC,
            rustix::io::Errno::ILSEQ => Self::EILSEQ,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::RESTART => Self::ERESTART,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::STRPIPE => Self::ESTRPIPE,
            rustix::io::Errno::USERS => Self::EUSERS,
            rustix::io::Errno::NOTSOCK => Self::ENOTSOCK,
            rustix::io::Errno::DESTADDRREQ => Self::EDESTADDRREQ,
            rustix::io::Errno::MSGSIZE => Self::EMSGSIZE,
            rustix::io::Errno::PROTOTYPE => Self::EPROTOTYPE,
            rustix::io::Errno::NOPROTOOPT => Self::ENOPROTOOPT,
            rustix::io::Errno::PROTONOSUPPORT => Self::EPROTONOSUPPORT,
            rustix::io::Errno::SOCKTNOSUPPORT => Self::ESOCKTNOSUPPORT,
            rustix::io::Errno::OPNOTSUPP => Self::EOPNOTSUPP,
            rustix::io::Errno::PFNOSUPPORT => Self::EPFNOSUPPORT,
            rustix::io::Errno::AFNOSUPPORT => Self::EAFNOSUPPORT,
            rustix::io::Errno::ADDRINUSE => Self::EADDRINUSE,
            rustix::io::Errno::ADDRNOTAVAIL => Self::EADDRNOTAVAIL,
            rustix::io::Errno::NETDOWN => Self::ENETDOWN,
            rustix::io::Errno::NETUNREACH => Self::ENETUNREACH,
            rustix::io::Errno::NETRESET => Self::ENETRESET,
            rustix::io::Errno::CONNABORTED => Self::ECONNABORTED,
            rustix::io::Errno::CONNRESET => Self::ECONNRESET,
            rustix::io::Errno::NOBUFS => Self::ENOBUFS,
            rustix::io::Errno::ISCONN => Self::EISCONN,
            rustix::io::Errno::NOTCONN => Self::ENOTCONN,
            rustix::io::Errno::SHUTDOWN => Self::ESHUTDOWN,
            rustix::io::Errno::TOOMANYREFS => Self::ETOOMANYREFS,
            rustix::io::Errno::TIMEDOUT => Self::ETIMEDOUT,
            rustix::io::Errno::CONNREFUSED => Self::ECONNREFUSED,
            rustix::io::Errno::HOSTDOWN => Self::EHOSTDOWN,
            rustix::io::Errno::HOSTUNREACH => Self::EHOSTUNREACH,
            rustix::io::Errno::ALREADY => Self::EALREADY,
            rustix::io::Errno::INPROGRESS => Self::EINPROGRESS,
            rustix::io::Errno::STALE => Self::ESTALE,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::UCLEAN => Self::EUCLEAN,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOTNAM => Self::ENOTNAM,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NAVAIL => Self::ENAVAIL,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::ISNAM => Self::EISNAM,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::REMOTEIO => Self::EREMOTEIO,
            rustix::io::Errno::DQUOT => Self::EDQUOT,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOMEDIUM => Self::ENOMEDIUM,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::MEDIUMTYPE => Self::EMEDIUMTYPE,
            rustix::io::Errno::CANCELED => Self::ECANCELED,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOKEY => Self::ENOKEY,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::KEYEXPIRED => Self::EKEYEXPIRED,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::KEYREVOKED => Self::EKEYREVOKED,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::KEYREJECTED => Self::EKEYREJECTED,
            // These are present on neither NetBSD nor macOS.
            #[cfg(target_os = "linux")]
            rustix::io::Errno::OWNERDEAD => Self::EOWNERDEAD,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::NOTRECOVERABLE => Self::ENOTRECOVERABLE,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::RFKILL => Self::ERFKILL,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::HWPOISON => Self::EHWPOISON,

            rustix::io::Errno::WOULDBLOCK => Self::EAGAIN,
            rustix::io::Errno::NOTSUP => Self::EOPNOTSUPP,
            #[cfg(target_os = "linux")]
            rustix::io::Errno::DEADLOCK => Self::EDEADLK,
            #[cfg(target_os = "netbsd")]
            rustix::io::Errno::FTYPE => Self::ELOOP,
            _ => Self::EINVAL,
        }
    }
}

/// A trait to allow logging and scripting of error values.
pub trait ExtendedError: std::error::Error {
    /// The types of errors.
    ///
    /// This provides a list of string error types that classify this error.  For example, a
    /// credential error that wraps an I/O error might indicate `["credential-error", "io-error"].
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]>;
    /// The tag of an error.
    ///
    /// This tag represents the error as a simple dash-divided string that indicates this specific
    /// error.  This will usually be a kebab-case version of the error kind.
    fn error_tag(&self) -> Cow<'static, str>;
}

impl<T: ExtendedError + ?Sized> ExtendedError for &T {
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]> {
        (*self).error_types()
    }

    fn error_tag(&self) -> Cow<'static, str> {
        (*self).error_tag()
    }
}

impl ExtendedError for Error {
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("errno")])
    }

    fn error_tag(&self) -> Cow<'static, str> {
        let s = format!("{:?}", self);
        s.to_ascii_lowercase().into()
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, ExtendedError};
    use std::borrow::{Borrow, Cow};

    #[test]
    fn test_extended_errors() {
        let e = Error::EIO;
        let v = e.error_types();
        let types: &[Cow<'static, str>] = v.borrow();
        assert_eq!(types, &[Cow::Borrowed("errno")]);
        assert_eq!(e.error_tag(), "eio");

        let e = Error::ELOOP;
        let v = e.error_types();
        let types: &[Cow<'static, str>] = v.borrow();
        assert_eq!(types, &[Cow::Borrowed("errno")]);
        assert_eq!(e.error_tag(), "eloop");
    }
}
