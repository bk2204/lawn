use crate::config::Logger;
use lawn_protocol::protocol::{
    ChannelCommandTTYMetadata, ChannelCommandTTYSizeMetadata, TerminalMode,
};
use num_traits::FromPrimitive;
use rustix::fd::BorrowedFd;
use rustix::termios::{self, OptionalActions, Termios, Winsize};
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;
use std::sync::Arc;

macro_rules! iflag_to_termios {
    ($termios:expr, $val:expr, $tflag:expr) => {{
        if let Value::Bool(val) = $val {
            if val {
                $termios.c_iflag |= $tflag;
            } else {
                $termios.c_iflag &= !$tflag;
            }
        }
    }};
}

macro_rules! oflag_to_termios {
    ($termios:expr, $val:expr, $tflag:expr) => {{
        if let Value::Bool(val) = $val {
            if val {
                $termios.c_oflag |= $tflag;
            } else {
                $termios.c_oflag &= !$tflag;
            }
        }
    }};
}

macro_rules! lflag_to_termios {
    ($termios:expr, $val:expr, $tflag:expr) => {{
        if let Value::Bool(val) = $val {
            if val {
                $termios.c_lflag |= $tflag;
            } else {
                $termios.c_lflag &= !$tflag;
            }
        }
    }};
}

macro_rules! cflag_to_termios {
    ($termios:expr, $val:expr, $tflag:expr) => {{
        if let Value::Bool(val) = $val {
            if val {
                $termios.c_cflag |= $tflag;
            } else {
                $termios.c_cflag &= !$tflag;
            }
        }
    }};
}

macro_rules! char_to_termios {
    ($termios:expr, $val:expr, $tval:expr) => {{
        match $val {
            Value::Null => $termios.c_cc[$tval as usize] = libc::_POSIX_VDISABLE,
            Value::Integer(x) => $termios.c_cc[$tval as usize] = x as libc::cc_t,
            _ => (),
        }
    }};
}

macro_rules! iflag_from_termios {
    ($settings:expr, $termios:expr, $tflag:expr, $opt:expr) => {{
        $settings.insert($opt as u32, Value::Bool(($termios.c_iflag & $tflag) != 0));
    }};
}

macro_rules! oflag_from_termios {
    ($settings:expr, $termios:expr, $tflag:expr, $opt:expr) => {{
        $settings.insert($opt as u32, Value::Bool(($termios.c_oflag & $tflag) != 0));
    }};
}

macro_rules! cflag_from_termios {
    ($settings:expr, $termios:expr, $tflag:expr, $opt:expr) => {{
        $settings.insert($opt as u32, Value::Bool(($termios.c_cflag & $tflag) != 0));
    }};
}

macro_rules! lflag_from_termios {
    ($settings:expr, $termios:expr, $tflag:expr, $opt:expr) => {{
        $settings.insert($opt as u32, Value::Bool(($termios.c_lflag & $tflag) != 0));
    }};
}

macro_rules! char_from_termios {
    ($settings:expr, $termios:expr, $tval:expr, $opt:expr) => {{
        let v = $termios.c_cc[$tval as usize];
        let vti = if v == libc::_POSIX_VDISABLE {
            Value::Null
        } else {
            Value::Integer(v as i128)
        };
        $settings.insert($opt as u32, vti);
    }};
}

#[derive(Clone)]
pub struct TTYSettings {
    settings: BTreeMap<u32, Value>,
    size: ChannelCommandTTYSizeMetadata,
    termios: Option<Termios>,
    logger: Arc<Logger>,
}

impl fmt::Debug for TTYSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TTYSettings")
            .field("settings", &self.settings)
            .field("size", &self.size)
            .finish()
    }
}

impl TTYSettings {
    #[allow(dead_code)]
    pub fn new(
        logger: Arc<Logger>,
        settings: BTreeMap<u32, Value>,
        size: &ChannelCommandTTYSizeMetadata,
    ) -> Self {
        Self {
            settings,
            size: size.clone(),
            termios: None,
            logger,
        }
    }

    #[allow(dead_code)]
    pub fn from_cbor_map(
        logger: Arc<Logger>,
        settings: BTreeMap<Value, Value>,
        size: &ChannelCommandTTYSizeMetadata,
    ) -> Self {
        let settings = settings
            .iter()
            .filter_map(|(k, v)| match k {
                Value::Integer(x) => {
                    let k = (*x).try_into().ok()?;
                    Some((k, v.clone()))
                }
                _ => None,
            })
            .collect();
        Self {
            settings,
            size: size.clone(),
            termios: None,
            logger,
        }
    }

    pub fn from_protocol_message(
        logger: Arc<Logger>,
        settings: &ChannelCommandTTYMetadata,
    ) -> Self {
        let mut modes: BTreeMap<_, _> = BTreeMap::new();
        let set = [
            TerminalMode::ECHO,
            TerminalMode::ISIG,
            TerminalMode::ICANON,
            TerminalMode::OPOST,
            TerminalMode::ONLCR,
            TerminalMode::ICRNL,
        ];
        for flag in set {
            modes.insert(flag as u32, Value::Bool(true));
        }
        modes.extend(settings.modes.iter().filter_map(|(mode, value)| {
            if (*mode & 0xffff0000) == 0x00010000 {
                None
            } else {
                Some((*mode, value.clone()))
            }
        }));
        modes.insert(TerminalMode::VMIN as u32, Value::Integer(1));
        modes.insert(TerminalMode::VTIME as u32, Value::Integer(0));

        Self {
            settings: modes,
            size: settings.size.clone(),
            termios: None,
            logger,
        }
    }

    #[allow(dead_code)]
    pub fn as_map(&self) -> &BTreeMap<u32, Value> {
        &self.settings
    }

    pub fn as_size(&self) -> &ChannelCommandTTYSizeMetadata {
        &self.size
    }

    pub fn to_cbor_map(&self) -> BTreeMap<Value, Value> {
        self.settings
            .iter()
            .map(|(k, v)| (Value::Integer(*k as i128), v.clone()))
            .collect()
    }

    pub fn set_raw(&mut self) {
        let clear = [
            TerminalMode::PARMRK,
            TerminalMode::ISTRIP,
            TerminalMode::INLCR,
            TerminalMode::IGNCR,
            TerminalMode::ICRNL,
            TerminalMode::IXON,
            TerminalMode::IXANY,
            TerminalMode::IXOFF,
            TerminalMode::IUCLC,
            TerminalMode::ISIG,
            TerminalMode::ICANON,
            TerminalMode::ECHO,
            TerminalMode::ECHOE,
            TerminalMode::ECHOK,
            TerminalMode::ECHONL,
            TerminalMode::IEXTEN,
            TerminalMode::OPOST,
        ];
        for flag in clear {
            self.settings.insert(flag as u32, Value::Bool(false));
        }
        let set = [TerminalMode::IGNPAR, TerminalMode::CS8];
        for flag in set {
            self.settings.insert(flag as u32, Value::Bool(true));
        }
        self.settings
            .insert(TerminalMode::VMIN as u32, Value::Integer(1));
        self.settings
            .insert(TerminalMode::VTIME as u32, Value::Integer(0));
    }

    pub fn set_termios(&mut self, tios: Termios) {
        self.termios = Some(tios);
    }

    pub fn set_size(&mut self, size: &ChannelCommandTTYSizeMetadata) {
        self.size = size.clone();
    }

    pub fn from_tty(logger: Arc<Logger>, fd: RawFd) -> Result<Self, std::io::Error> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let tios = termios::tcgetattr(fd)?;
        let wsize = termios::tcgetwinsize(fd)?;
        Ok(Self {
            settings: Self::from_termios(tios),
            size: Self::from_ioctl(wsize),
            termios: Some(tios),
            logger,
        })
    }

    pub fn set_tty(&self, fd: RawFd, now: bool) -> Result<(), std::io::Error> {
        self.set_tty_size(fd)?;
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let tios = self.termios();
        termios::tcsetattr(
            fd,
            if now {
                OptionalActions::Now
            } else {
                OptionalActions::Drain
            },
            &tios,
        )?;
        Ok(())
    }

    pub fn set_tty_size(&self, fd: RawFd) -> Result<(), std::io::Error> {
        let fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let wsize = self.winsize();
        termios::tcsetwinsize(fd, wsize)?;
        Ok(())
    }

    fn from_ioctl(wsize: Winsize) -> ChannelCommandTTYSizeMetadata {
        ChannelCommandTTYSizeMetadata {
            height_cells: wsize.ws_row as u32,
            width_cells: wsize.ws_col as u32,
            height_pixels: wsize.ws_ypixel as u32,
            width_pixels: wsize.ws_xpixel as u32,
        }
    }

    fn from_termios(tios: Termios) -> BTreeMap<u32, Value> {
        let mut settings = BTreeMap::new();
        let ispeed = termios::cfgetispeed(&tios);
        if let Some(ispeed) = Self::speed_to_int(ispeed) {
            settings.insert(
                TerminalMode::TTY_OP_ISPEED as u32,
                Value::Integer(ispeed as i128),
            );
        }
        let ospeed = termios::cfgetospeed(&tios);
        if let Some(ospeed) = Self::speed_to_int(ospeed) {
            settings.insert(
                TerminalMode::TTY_OP_OSPEED as u32,
                Value::Integer(ospeed as i128),
            );
        }
        iflag_from_termios!(
            settings,
            tios,
            rustix::termios::IGNPAR,
            TerminalMode::IGNPAR
        );
        iflag_from_termios!(
            settings,
            tios,
            rustix::termios::PARMRK,
            TerminalMode::PARMRK
        );
        iflag_from_termios!(settings, tios, rustix::termios::INPCK, TerminalMode::INPCK);
        iflag_from_termios!(
            settings,
            tios,
            rustix::termios::ISTRIP,
            TerminalMode::ISTRIP
        );
        iflag_from_termios!(settings, tios, rustix::termios::INLCR, TerminalMode::INLCR);
        iflag_from_termios!(settings, tios, rustix::termios::IGNCR, TerminalMode::IGNCR);
        iflag_from_termios!(settings, tios, rustix::termios::ICRNL, TerminalMode::ICRNL);
        #[cfg(not(target_os = "macos"))]
        iflag_from_termios!(settings, tios, rustix::termios::IUCLC, TerminalMode::IUCLC);
        iflag_from_termios!(settings, tios, rustix::termios::IXON, TerminalMode::IXON);
        iflag_from_termios!(settings, tios, rustix::termios::IXANY, TerminalMode::IXANY);
        iflag_from_termios!(settings, tios, rustix::termios::IXOFF, TerminalMode::IXOFF);
        iflag_from_termios!(
            settings,
            tios,
            rustix::termios::IMAXBEL,
            TerminalMode::IMAXBEL
        );
        iflag_from_termios!(settings, tios, rustix::termios::IUTF8, TerminalMode::IUTF8);

        oflag_from_termios!(settings, tios, rustix::termios::OPOST, TerminalMode::OPOST);
        #[cfg(not(target_os = "macos"))]
        oflag_from_termios!(settings, tios, rustix::termios::OLCUC, TerminalMode::OLCUC);
        oflag_from_termios!(settings, tios, rustix::termios::ONLCR, TerminalMode::ONLCR);
        oflag_from_termios!(settings, tios, rustix::termios::OCRNL, TerminalMode::OCRNL);
        oflag_from_termios!(
            settings,
            tios,
            rustix::termios::ONLRET,
            TerminalMode::ONLRET
        );

        lflag_from_termios!(settings, tios, rustix::termios::ISIG, TerminalMode::ISIG);
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::ICANON,
            TerminalMode::ICANON
        );
        #[cfg(not(target_os = "macos"))]
        lflag_from_termios!(settings, tios, rustix::termios::XCASE, TerminalMode::XCASE);
        lflag_from_termios!(settings, tios, rustix::termios::ECHO, TerminalMode::ECHO);
        lflag_from_termios!(settings, tios, rustix::termios::ECHOE, TerminalMode::ECHOE);
        lflag_from_termios!(settings, tios, rustix::termios::ECHOK, TerminalMode::ECHOK);
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::ECHONL,
            TerminalMode::ECHONL
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::NOFLSH,
            TerminalMode::NOFLSH
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::TOSTOP,
            TerminalMode::TOSTOP
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::IEXTEN,
            TerminalMode::IEXTEN
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::ECHOCTL,
            TerminalMode::ECHOCTL
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::ECHOKE,
            TerminalMode::ECHOKE
        );
        lflag_from_termios!(
            settings,
            tios,
            rustix::termios::PENDIN,
            TerminalMode::PENDIN
        );

        cflag_from_termios!(
            settings,
            tios,
            rustix::termios::PARENB,
            TerminalMode::PARENB
        );
        cflag_from_termios!(
            settings,
            tios,
            rustix::termios::PARODD,
            TerminalMode::PARODD
        );

        char_from_termios!(settings, tios, rustix::termios::VINTR, TerminalMode::VINTR);
        char_from_termios!(settings, tios, rustix::termios::VQUIT, TerminalMode::VQUIT);
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VERASE,
            TerminalMode::VERASE
        );
        char_from_termios!(settings, tios, rustix::termios::VKILL, TerminalMode::VKILL);
        char_from_termios!(settings, tios, rustix::termios::VEOF, TerminalMode::VEOF);
        char_from_termios!(settings, tios, rustix::termios::VEOL, TerminalMode::VEOL);
        char_from_termios!(settings, tios, rustix::termios::VEOL2, TerminalMode::VEOL2);
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VSTART,
            TerminalMode::VSTART
        );
        char_from_termios!(settings, tios, rustix::termios::VSTOP, TerminalMode::VSTOP);
        char_from_termios!(settings, tios, rustix::termios::VSUSP, TerminalMode::VSUSP);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VDSUSP,
            TerminalMode::VDSUSP
        );
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VREPRINT,
            TerminalMode::VREPRINT
        );
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VWERASE,
            TerminalMode::VWERASE
        );
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VLNEXT,
            TerminalMode::VLNEXT
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VFLUSH,
            TerminalMode::VFLUSH
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VSWTCH,
            TerminalMode::VSWTCH
        );
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VSTATUS,
            TerminalMode::VSTATUS
        );
        char_from_termios!(
            settings,
            tios,
            rustix::termios::VDISCARD,
            TerminalMode::VDISCARD
        );
        char_from_termios!(settings, tios, rustix::termios::VMIN, TerminalMode::VMIN);
        char_from_termios!(settings, tios, rustix::termios::VTIME, TerminalMode::VTIME);

        match tios.c_cflag & libc::CSIZE {
            libc::CS7 => {
                settings.insert(TerminalMode::CS7 as u32, Value::Bool(true));
            }
            libc::CS8 => {
                settings.insert(TerminalMode::CS8 as u32, Value::Bool(true));
            }
            _ => (),
        }
        settings
    }

    pub fn termios(&self) -> Termios {
        let mut tios = match self.termios {
            Some(t) => t,
            None => {
                let tios = MaybeUninit::zeroed();
                unsafe { tios.assume_init() }
            }
        };
        for (key, value) in &self.settings {
            match TerminalMode::from_u32(*key) {
                Some(TerminalMode::IGNPAR) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IGNPAR)
                }
                Some(TerminalMode::PARMRK) => {
                    iflag_to_termios!(tios, *value, rustix::termios::PARMRK)
                }
                Some(TerminalMode::INPCK) => {
                    iflag_to_termios!(tios, *value, rustix::termios::INPCK)
                }
                Some(TerminalMode::ISTRIP) => {
                    iflag_to_termios!(tios, *value, rustix::termios::ISTRIP)
                }
                Some(TerminalMode::INLCR) => {
                    iflag_to_termios!(tios, *value, rustix::termios::INLCR)
                }
                Some(TerminalMode::IGNCR) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IGNCR)
                }
                Some(TerminalMode::ICRNL) => {
                    iflag_to_termios!(tios, *value, rustix::termios::ICRNL)
                }
                #[cfg(not(target_os = "macos"))]
                Some(TerminalMode::IUCLC) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IUCLC)
                }
                Some(TerminalMode::IXON) => iflag_to_termios!(tios, *value, rustix::termios::IXON),
                Some(TerminalMode::IXANY) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IXANY)
                }
                Some(TerminalMode::IXOFF) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IXOFF)
                }
                Some(TerminalMode::IMAXBEL) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IMAXBEL)
                }
                Some(TerminalMode::IUTF8) => {
                    iflag_to_termios!(tios, *value, rustix::termios::IUTF8)
                }

                Some(TerminalMode::OPOST) => {
                    oflag_to_termios!(tios, *value, rustix::termios::OPOST)
                }
                #[cfg(not(target_os = "macos"))]
                Some(TerminalMode::OLCUC) => {
                    oflag_to_termios!(tios, *value, rustix::termios::OLCUC)
                }
                Some(TerminalMode::ONLCR) => {
                    oflag_to_termios!(tios, *value, rustix::termios::ONLCR)
                }
                Some(TerminalMode::OCRNL) => {
                    oflag_to_termios!(tios, *value, rustix::termios::OCRNL)
                }
                Some(TerminalMode::ONLRET) => {
                    oflag_to_termios!(tios, *value, rustix::termios::ONLRET)
                }

                Some(TerminalMode::ISIG) => lflag_to_termios!(tios, *value, rustix::termios::ISIG),
                Some(TerminalMode::ICANON) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ICANON)
                }
                #[cfg(not(target_os = "macos"))]
                Some(TerminalMode::XCASE) => {
                    lflag_to_termios!(tios, *value, rustix::termios::XCASE)
                }
                Some(TerminalMode::ECHO) => lflag_to_termios!(tios, *value, rustix::termios::ECHO),
                Some(TerminalMode::ECHOE) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ECHOE)
                }
                Some(TerminalMode::ECHOK) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ECHOK)
                }
                Some(TerminalMode::ECHONL) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ECHONL)
                }
                Some(TerminalMode::NOFLSH) => {
                    lflag_to_termios!(tios, *value, rustix::termios::NOFLSH)
                }
                Some(TerminalMode::TOSTOP) => {
                    lflag_to_termios!(tios, *value, rustix::termios::TOSTOP)
                }
                Some(TerminalMode::IEXTEN) => {
                    lflag_to_termios!(tios, *value, rustix::termios::IEXTEN)
                }
                Some(TerminalMode::ECHOCTL) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ECHOCTL)
                }
                Some(TerminalMode::ECHOKE) => {
                    lflag_to_termios!(tios, *value, rustix::termios::ECHOKE)
                }
                Some(TerminalMode::PENDIN) => {
                    lflag_to_termios!(tios, *value, rustix::termios::PENDIN)
                }

                Some(TerminalMode::PARENB) => {
                    cflag_to_termios!(tios, *value, rustix::termios::PARENB)
                }
                Some(TerminalMode::PARODD) => {
                    cflag_to_termios!(tios, *value, rustix::termios::PARODD)
                }

                Some(TerminalMode::VINTR) => char_to_termios!(tios, *value, rustix::termios::VINTR),
                Some(TerminalMode::VQUIT) => char_to_termios!(tios, *value, rustix::termios::VQUIT),
                Some(TerminalMode::VERASE) => {
                    char_to_termios!(tios, *value, rustix::termios::VERASE)
                }
                Some(TerminalMode::VKILL) => char_to_termios!(tios, *value, rustix::termios::VKILL),
                Some(TerminalMode::VEOF) => char_to_termios!(tios, *value, rustix::termios::VEOF),
                Some(TerminalMode::VEOL) => char_to_termios!(tios, *value, rustix::termios::VEOL),
                Some(TerminalMode::VEOL2) => char_to_termios!(tios, *value, rustix::termios::VEOL2),
                Some(TerminalMode::VSTART) => {
                    char_to_termios!(tios, *value, rustix::termios::VSTART)
                }
                Some(TerminalMode::VSTOP) => char_to_termios!(tios, *value, rustix::termios::VSTOP),
                Some(TerminalMode::VSUSP) => char_to_termios!(tios, *value, rustix::termios::VSUSP),
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                Some(TerminalMode::VDSUSP) => {
                    char_to_termios!(tios, *value, rustix::termios::VDSUSP)
                }
                Some(TerminalMode::VREPRINT) => {
                    char_to_termios!(tios, *value, rustix::termios::VREPRINT)
                }
                Some(TerminalMode::VWERASE) => {
                    char_to_termios!(tios, *value, rustix::termios::VWERASE)
                }
                Some(TerminalMode::VLNEXT) => {
                    char_to_termios!(tios, *value, rustix::termios::VLNEXT)
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                Some(TerminalMode::VFLUSH) => {
                    char_to_termios!(tios, *value, rustix::termios::VFLUSH)
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                Some(TerminalMode::VSWTCH) => {
                    char_to_termios!(tios, *value, rustix::termios::VSWTCH)
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                Some(TerminalMode::VSTATUS) => {
                    char_to_termios!(tios, *value, rustix::termios::VSTATUS)
                }
                Some(TerminalMode::VDISCARD) => {
                    char_to_termios!(tios, *value, rustix::termios::VDISCARD)
                }
                Some(TerminalMode::VMIN) => char_to_termios!(tios, *value, rustix::termios::VMIN),
                Some(TerminalMode::VTIME) => char_to_termios!(tios, *value, rustix::termios::VTIME),

                Some(TerminalMode::CS7) => {
                    if let Value::Bool(val) = value {
                        tios.c_cflag &= !rustix::termios::CSIZE;
                        if *val {
                            tios.c_cflag |= rustix::termios::CS7;
                        }
                    }
                }
                Some(TerminalMode::CS8) => {
                    if let Value::Bool(val) = value {
                        tios.c_cflag &= !rustix::termios::CSIZE;
                        if *val {
                            tios.c_cflag |= rustix::termios::CS8;
                        }
                    }
                }
                Some(TerminalMode::TTY_OP_ISPEED) => {
                    if let Value::Integer(speed) = value {
                        if let Some(speed) = Self::int_to_speed(*speed as u32) {
                            let _ = termios::cfsetispeed(&mut tios, speed);
                        }
                    }
                }
                Some(TerminalMode::TTY_OP_OSPEED) => {
                    if let Value::Integer(speed) = value {
                        if let Some(speed) = Self::int_to_speed(*speed as u32) {
                            let _ = termios::cfsetospeed(&mut tios, speed);
                        }
                    }
                }
                Some(n) => {
                    debug!(
                        self.logger,
                        "unhandled key {} processing terminal modes", n as u32
                    );
                }
                None => {
                    debug!(
                        self.logger,
                        "unknown key {} processing terminal modes", *key
                    );
                }
            }
        }
        tios
    }

    pub fn winsize(&self) -> Winsize {
        Winsize {
            ws_row: self.size.height_cells as u16,
            ws_col: self.size.width_cells as u16,
            ws_ypixel: self.size.height_pixels as u16,
            ws_xpixel: self.size.width_pixels as u16,
        }
    }

    fn speed_to_int(speed: termios::Speed) -> Option<u32> {
        match speed {
            libc::B0 => Some(0),
            libc::B50 => Some(50),
            libc::B75 => Some(75),
            libc::B110 => Some(110),
            libc::B150 => Some(150),
            libc::B200 => Some(200),
            libc::B300 => Some(300),
            libc::B600 => Some(600),
            libc::B1200 => Some(1200),
            libc::B1800 => Some(1800),
            libc::B2400 => Some(2400),
            libc::B4800 => Some(4800),
            libc::B9600 => Some(9600),
            libc::B19200 => Some(19200),
            libc::B38400 => Some(38400),
            _ => None,
        }
    }

    fn int_to_speed(speed: u32) -> Option<termios::Speed> {
        match speed {
            0 => Some(libc::B0),
            50 => Some(libc::B50),
            75 => Some(libc::B75),
            110 => Some(libc::B110),
            150 => Some(libc::B150),
            200 => Some(libc::B200),
            300 => Some(libc::B300),
            600 => Some(libc::B600),
            1200 => Some(libc::B1200),
            1800 => Some(libc::B1800),
            2400 => Some(libc::B2400),
            4800 => Some(libc::B4800),
            9600 => Some(libc::B9600),
            19200 => Some(libc::B19200),
            38400 => Some(libc::B38400),
            _ => None,
        }
    }
}
