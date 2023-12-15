use super::helpers::{BoxedCredentialBackendHandleIterator, CommandCredentialBackend};
use super::{CredentialBackendHandle, CredentialElements};
use crate::config::{self, Config};
use crate::credential::protocol::git::GitProtocolHandler;
use crate::credential::{Credential, CredentialParserError, CredentialRequest};
use crate::store::{StoreAuthenticationMetadata, StorePath};
use bytes::Bytes;
use lawn_protocol::protocol::{self, ResponseCode, StoreSelectorID};
use std::any::Any;
use std::borrow::Cow;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub struct GitCredentialBackend {
    config: Arc<Config>,
    name: Bytes,
    command: String,
    next_id: Arc<AtomicU32>,
    elems: CredentialElements,
}

impl GitCredentialBackend {
    pub fn new(
        config: Arc<Config>,
        elems: CredentialElements,
        ids: Arc<AtomicU32>,
        name: Bytes,
        command: &str,
    ) -> Self {
        Self {
            config,
            name,
            command: command.to_owned(),
            next_id: ids,
            elems,
        }
    }

    fn create_command(
        &self,
        subcommand: Bytes,
    ) -> Result<std::process::Command, crate::error::Error> {
        let args = Arc::new([subcommand]);
        let ctx = self.config.template_context(None, Some(args));
        Ok(config::Command::new_simple(&self.command, &ctx)?.run_std_command())
    }

    fn do_write_credential_op(
        &self,
        command: &'static str,
        req: &Credential,
    ) -> Result<Bytes, CredentialParserError> {
        let mut cmd = self
            .create_command(Bytes::from(command))
            .map_err(|_| CredentialParserError::SpawnError)?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn()?;
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let proto = GitProtocolHandler::new(
            Arc::new(Mutex::new(stdout)),
            Arc::new(Mutex::new(stdin)),
            None,
            None,
            None,
        );
        proto.clone().send_approve_reject_request(req)?;
        proto.close_writer();
        let _ = child.wait();
        let components: &[&[u8]] = &[b"", self.backend_name(), b"-", &req.id];
        let path = StorePath::from_components(components).unwrap().into_inner();
        Ok(path)
    }
}

impl CommandCredentialBackend for GitCredentialBackend {
    type Backend = Arc<Self>;

    fn config(self: Arc<Self>) -> Arc<Config> {
        self.config.clone()
    }

    fn backend_name(&self) -> &[u8] {
        self.name.as_ref()
    }

    fn backend_type(&self) -> &str {
        "git"
    }

    fn needs_authentication(&self) -> bool {
        false
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        None
    }

    fn authenticate(
        &self,
        _kind: Bytes,
        _message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn list_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError> {
        Ok(Cow::Owned([Bytes::from(b"-" as &[u8])].into()))
    }

    fn next_id(self: Arc<Self>) -> StoreSelectorID {
        StoreSelectorID(self.next_id.fetch_add(1, Ordering::AcqRel))
    }

    fn insert_handle(
        self: Arc<Self>,
        id: StoreSelectorID,
        handle: Arc<dyn CredentialBackendHandle + Send + Sync>,
    ) {
        self.elems.write().unwrap().insert(id, handle.clone());
    }

    fn get_handle(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Option<Arc<dyn CredentialBackendHandle + Send + Sync>> {
        self.elems.read().unwrap().get(&id).cloned()
    }

    fn search_credential(
        self: Arc<Self>,
        _id: StoreSelectorID,
        req: &CredentialRequest,
    ) -> Result<Option<(Credential, Bytes)>, CredentialParserError> {
        let logger = self.config.logger();
        let mut cmd = self
            .create_command(Bytes::from("fill"))
            .map_err(|_| CredentialParserError::SpawnError)?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => return Err(e.into()),
        };
        let (stdin, stdout) = (child.stdin.take().unwrap(), child.stdout.take().unwrap());
        let proto = GitProtocolHandler::new(
            Arc::new(Mutex::new(stdout)),
            Arc::new(Mutex::new(stdin)),
            None,
            None,
            None,
        );
        match proto.clone().send_fill_request(req) {
            Ok(()) => (),
            Err(e) => {
                trace!(
                    logger,
                    "server: git credential: read: send fill request failed: {:?}",
                    e
                );
                return Err(e);
            }
        }
        proto.clone().close_writer();
        let r = proto.parse_fill_response();
        let _ = child.wait();
        match r {
            Ok(Some(cred)) => {
                let id = cred.id();
                match StorePath::from_components::<&[u8]>(&[b"", self.backend_name(), b"-", &id]) {
                    Some(path) => Ok(Some((cred, path.into_inner()))),
                    None => Ok(None),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => {
                trace!(
                    logger,
                    "server: git credential: read: parsing fill response failed: {:?}",
                    e
                );
                Err(e)
            }
        }
    }

    fn write_credential(
        self: Arc<Self>,
        _id: StoreSelectorID,
        cred: &Credential,
        _overwrite: bool,
        _create: bool,
    ) -> Result<Bytes, CredentialParserError> {
        self.do_write_credential_op("approve", cred)
    }

    fn delete_credential(
        self: Arc<Self>,
        _id: StoreSelectorID,
        cred: &Credential,
    ) -> Result<(), CredentialParserError> {
        self.do_write_credential_op("reject", cred)?;
        Ok(())
    }

    fn delete_credential_by_id(
        self: Arc<Self>,
        _id: StoreSelectorID,
    ) -> Result<(), CredentialParserError> {
        Err(CredentialParserError::Unlistable)
    }

    fn listable(&self) -> bool {
        false
    }

    fn list_entries(
        self: Arc<Self>,
        _id: StoreSelectorID,
    ) -> Result<Option<BoxedCredentialBackendHandleIterator>, protocol::Error> {
        Err(ResponseCode::Unlistable.into())
    }

    fn create_directory(self: Arc<Self>, _path: Bytes) -> Result<(), protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn exists(self: Arc<Self>, _path: Bytes) -> Result<bool, CredentialParserError> {
        Err(CredentialParserError::Unlistable)
    }

    fn read_body(
        self: Arc<Self>,
        _id: StoreSelectorID,
    ) -> Result<Option<Box<dyn Any + 'static>>, protocol::Error> {
        Err(ResponseCode::Unlistable.into())
    }
}
