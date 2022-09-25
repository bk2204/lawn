use super::{AuthenticationInfo, Authenticator, Result};
use crate::backend::ToIdentifier;
use lawn_constants::Error;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ExternalAuthenticatorHandle {
    user: Vec<u8>,
    dir: Vec<u8>,
    id: Option<u32>,
}

impl ToIdentifier for ExternalAuthenticatorHandle {
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

pub struct ExternalAuthenticator {}

impl Authenticator for ExternalAuthenticator {
    type SessionHandle = ExternalAuthenticatorHandle;

    fn create(&self, uname: &[u8], aname: &[u8], nuname: Option<u32>) -> Self::SessionHandle {
        Self::SessionHandle {
            user: uname.into(),
            dir: aname.into(),
            id: nuname,
        }
    }

    fn read(&self, _handle: &mut Self::SessionHandle, _data: &mut [u8]) -> Result<u32> {
        Err(Error::EOPNOTSUPP)
    }

    fn write(&self, _handle: &mut Self::SessionHandle, _data: &[u8]) -> Result<u32> {
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
