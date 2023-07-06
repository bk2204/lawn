use crate::backend::Metadata;
use lawn_constants::Error;

/// A set of tools to implement authentication and location finding.
///
/// Each authenticator is responsible for determining whether and what access is to be granted,
/// performing authentication, and, if the user is authenticated, providing the location of the
/// root of the mount.
///
/// This is done by creating an instance of the `Authenticator` trait, which can create handles,
/// and then

type Result<T> = std::result::Result<T, Error>;

/// Information about a successful authentication.
pub struct AuthenticationInfo<'a> {
    id: Option<u32>,
    user: &'a [u8],
    dir: &'a [u8],
    location: &'a [u8],
}

impl<'a> AuthenticationInfo<'a> {
    /// Create a new instance.
    ///
    /// `id` is the user ID, if any.  `user` is the username.  `dir` is a directory associated with
    /// this user (usually their home directory), and `location` is the location of the mount
    /// point.  Note that usually `dir` is the same as `location`.
    pub fn new(
        id: Option<u32>,
        user: &'a [u8],
        dir: &'a [u8],
        location: &'a [u8],
    ) -> AuthenticationInfo<'a> {
        AuthenticationInfo {
            id,
            user,
            dir,
            location,
        }
    }

    /// The user ID of the authenticated user, if any.
    pub fn id(&self) -> Option<u32> {
        self.id
    }

    /// The username of this user, if any.
    pub fn user(&self) -> &[u8] {
        self.user
    }

    /// The user's home directory, which may be the same as `location`.
    pub fn dir(&self) -> &[u8] {
        self.dir
    }

    /// The location of the mount point.
    pub fn location(&self) -> &[u8] {
        self.location
    }
}

/// An authenticator handle.
pub trait AuthenticatorHandle {
    /// Read data from this authenticator.
    ///
    /// This reads data from the authenticator in an authenticator-specific protocol.
    fn read(&self, data: &mut [u8]) -> Result<u32>;
    /// Write data to this authenticator.
    ///
    /// This writes data to the authenticator in an authenticator-specific protocol.
    fn write(&self, data: &[u8]) -> Result<u32>;
    /// Determine if the user is authenticated and return information if so.
    ///
    /// This method is called once reads and writes from this handle are completed.  If the return
    /// value is `Some`, the user is authenticated, and the return value contains information about
    /// the access granted.  If the user is not authenticated, this returns `None`.
    fn info(&self) -> Option<AuthenticationInfo<'_>>;
}

/// A trait to authenticate and locate the root of a mount.
///
/// Each authenticator is responsible for determining whether and what access is to be granted,
/// performing authentication, and, if the user is authenticated, providing the location of the
pub trait Authenticator {
    /// Create a new authenticator handle.
    ///
    /// `uname` is the user name of the party wanting access, and `nuname` is the user ID, if any.
    /// `aname` indicates the resource for which access is requested.
    fn create(
        &self,
        meta: &Metadata,
        uname: &[u8],
        aname: &[u8],
        nuname: Option<u32>,
    ) -> Box<dyn AuthenticatorHandle + Send + Sync>;
}
