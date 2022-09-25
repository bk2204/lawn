use crate::backend;
use lawn_constants::Error;

pub mod external;

type Result<T> = std::result::Result<T, Error>;

pub struct AuthenticationInfo<'a> {
    id: Option<u32>,
    user: &'a [u8],
    dir: &'a [u8],
    location: &'a [u8],
}

impl<'a> AuthenticationInfo<'a> {
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

    pub fn id(&self) -> Option<u32> {
        self.id
    }

    pub fn user(&self) -> &[u8] {
        self.user
    }

    pub fn dir(&self) -> &[u8] {
        self.dir
    }

    pub fn location(&self) -> &[u8] {
        self.location
    }
}

pub trait Authenticator {
    type SessionHandle: backend::ToIdentifier;

    fn create(&self, uname: &[u8], aname: &[u8], nuname: Option<u32>) -> Self::SessionHandle;
    fn read(&self, handle: &mut Self::SessionHandle, data: &mut [u8]) -> Result<u32>;
    fn write(&self, handle: &mut Self::SessionHandle, data: &[u8]) -> Result<u32>;
    fn info<'a>(&self, handle: &'a Self::SessionHandle) -> Option<AuthenticationInfo<'a>>;
}
