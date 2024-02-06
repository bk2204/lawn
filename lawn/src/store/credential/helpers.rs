use super::{
    CredentialBackend, CredentialBackendHandle, CredentialBackendStoreElement,
    CredentialPathComponentType, CredentialVault,
};
use crate::config::Config;
use crate::credential::{Credential, CredentialParserError, CredentialRequest};
use crate::store::{
    StoreAuthenticationMetadata, StoreElement, StoreElementEntry, StoreElementEntryIterator,
    StorePath,
};
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_protocol::protocol::{
    self, CredentialStoreElement, CredentialStoreSearchElement, ResponseCode, StoreID,
    StoreSearchRecursionLevel, StoreSelectorID,
};
use serde_cbor::Value;
use std::any::Any;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};

pub struct CommandCredentialVault<
    T: Send + Sync + 'static,
    U: CommandCredentialBackend<Backend = T> + Sized + Send + Sync + 'static,
> {
    store_id: StoreID,
    id: StoreSelectorID,
    name: Bytes,
    parent: Arc<U>,
}

impl<
        T: Send + Sync + 'static,
        U: CommandCredentialBackend<Backend = T> + Send + Sync + 'static,
    > CredentialVault for CommandCredentialVault<T, U>
{
    fn name(&self) -> &[u8] {
        self.name.as_ref()
    }

    fn search(
        self: Arc<Self>,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    > {
        self.to_handle().search(kind, pattern, recurse)
    }

    fn to_handle(self: Arc<Self>) -> Arc<dyn CredentialBackendHandle + Send + Sync> {
        Arc::new(CommandCredentialBackendHandle {
            store_id: self.store_id,
            id: self.id,
            path: StoreElement::path(self.as_ref()),
            parent: Arc::clone(&self.parent),
            credential: Mutex::new(None),
        })
    }
}

impl<T: Send + Sync, U: CommandCredentialBackend<Backend = T> + Sized + Send + Sync + ?Sized>
    StoreElement for CommandCredentialVault<T, U>
{
    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn id(&self) -> StoreSelectorID {
        self.id
    }

    fn path(&self) -> Bytes {
        StorePath::from_components::<&[u8]>(&[
            b"",
            self.parent.backend_name(),
            self.name.as_ref(),
            b"",
        ])
        .unwrap()
        .into_inner()
    }

    fn kind(&self) -> &[u8] {
        b"directory"
    }

    fn contents(
        &self,
    ) -> Result<
        Option<Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>>,
        protocol::Error,
    > {
        let logger = self.parent.clone().config().logger();
        trace!(
            logger,
            "server: {} backend: contents: vault",
            self.parent.backend_type()
        );
        if !self.parent.listable() {
            return Err(ResponseCode::Unlistable.into());
        }
        let items = match self.parent.clone().list_entries(self.id) {
            Ok(Some(items)) => items.map(|item| item.to_store_element_entry()).collect(),
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(Some(Box::new(StoreElementEntryIterator::new(items))))
    }

    fn needs_authentication(&self) -> Option<bool> {
        Some(self.parent.needs_authentication())
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        self.parent.authentication_metadata()
    }

    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error> {
        self.parent.authenticate(kind, message)
    }

    fn update(
        self: Arc<Self>,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<(), protocol::Error> {
        self.to_handle().update(meta, body)
    }

    fn delete(&self) -> Result<(), protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>> {
        let mut map = BTreeMap::new();
        map.insert(
            Bytes::from(b"backend-type" as &'static [u8]),
            Value::Text(self.parent.backend_type().into()),
        );
        Some(Cow::Owned(map))
    }

    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn search(
        self: Arc<Self>,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    > {
        self.to_handle().search(kind, pattern, recurse)
    }

    fn create(
        self: Arc<Self>,
        path: Option<Bytes>,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        self.to_handle().create(path, kind, meta, body)
    }
}

pub struct CommandCredentialBackendHandle<
    T: Send + Sync,
    U: CommandCredentialBackend<Backend = T> + Send + Sync,
> {
    store_id: StoreID,
    id: StoreSelectorID,
    path: Bytes,
    parent: Arc<U>,
    credential: Mutex<Option<Credential>>,
}

impl<
        T: Send + Sync + 'static,
        U: CommandCredentialBackend<Backend = T> + Send + Sync + 'static,
    > CommandCredentialBackendHandle<T, U>
{
    pub(super) fn new(store_id: StoreID, id: StoreSelectorID, path: Bytes, parent: Arc<U>) -> Self {
        Self {
            store_id,
            id,
            path,
            parent,
            credential: Mutex::new(None),
        }
    }

    pub(super) fn new_with_credential(
        store_id: StoreID,
        id: StoreSelectorID,
        path: Bytes,
        parent: Arc<U>,
        cred: Credential,
    ) -> Self {
        Self {
            store_id,
            id,
            path,
            parent,
            credential: Mutex::new(Some(cred)),
        }
    }
}

impl<
        T: Send + Sync + 'static,
        U: CommandCredentialBackend<Backend = T> + Send + Sync + 'static,
    > CredentialBackendHandle for CommandCredentialBackendHandle<T, U>
{
    fn config(&self) -> Arc<Config> {
        self.parent.clone().config()
    }

    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn id(&self) -> StoreSelectorID {
        self.id
    }

    fn to_store_element_entry(self: Arc<Self>) -> Arc<dyn StoreElementEntry + Send + Sync> {
        Arc::new(CredentialBackendStoreElement {
            store_id: self.store_id,
            id: self.id,
            path: self.path.clone(),
            parent: self,
        })
    }

    fn to_store_element(self: Arc<Self>) -> Arc<dyn StoreElement + Send + Sync> {
        Arc::new(CredentialBackendStoreElement {
            store_id: self.store_id,
            id: self.id,
            path: self.path.clone(),
            parent: self,
        })
    }

    fn backend_name(&self) -> &[u8] {
        self.parent.backend_name()
    }

    fn backend_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError> {
        self.parent.list_vaults()
    }

    fn needs_authentication(&self) -> Option<bool> {
        Some(self.parent.needs_authentication())
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        self.parent.authentication_metadata()
    }

    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error> {
        self.parent.authenticate(kind, message)
    }

    fn update(
        self: Arc<Self>,
        _meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<(), protocol::Error> {
        let logger = self.parent.clone().config().logger();
        match CredentialPathComponentType::from_path(self.path.clone()) {
            Some(CredentialPathComponentType::Entry) => (),
            _ => return Err(ResponseCode::NotSupported.into()),
        }
        let c: &CredentialStoreElement =
            match body.and_then(|p| p.downcast_ref::<CredentialStoreElement>()) {
                Some(p) => p,
                None => return Err(ResponseCode::NotSupported.into()),
            };
        let c: Credential = c.try_into().map_err(|e| {
            trace!(logger, "server: failed to convert credential: {}", e);
            protocol::Error::from(ResponseCode::Invalid)
        })?;
        // TODO: use a better error code.
        self.parent
            .clone()
            .write_credential(self.id(), &c, true, false)
            .map_err(|e| match e {
                CredentialParserError::Unauthenticated => ResponseCode::NeedsAuthentication.into(),
                e => {
                    trace!(
                        logger,
                        "server: {} credential: update: error: {}",
                        self.parent.backend_type(),
                        e
                    );
                    protocol::Error::from(ResponseCode::InternalError)
                }
            })?;
        let mut g = self.credential.lock().unwrap();
        *g = Some(c);
        Ok(())
    }

    fn delete(&self) -> Result<(), protocol::Error> {
        let g = self.credential.lock().unwrap();
        match &*g {
            Some(c) => self
                .parent
                .clone()
                .delete_credential(self.id, c)
                .map_err(|e| {
                    let logger = self.parent.clone().config().logger();
                    trace!(
                        logger,
                        "server: {} credential: delete: error: {}",
                        self.parent.backend_type(),
                        e
                    );
                    protocol::Error::from(ResponseCode::InternalError)
                }),
            None => self
                .parent
                .clone()
                .delete_credential_by_id(self.id)
                .map_err(|e| match e {
                    CredentialParserError::Unlistable => {
                        protocol::Error::from(ResponseCode::Unlistable)
                    }
                    e => {
                        let logger = self.parent.clone().config().logger();
                        trace!(
                            logger,
                            "server: {} credential: delete by ID: error: {}",
                            self.parent.backend_type(),
                            e
                        );
                        protocol::Error::from(ResponseCode::InternalError)
                    }
                }),
        }
    }

    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>> {
        None
    }

    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error> {
        match self.credential.lock().unwrap().as_ref() {
            Some(c) => {
                let cse: CredentialStoreElement = c.into();
                Ok(Some(Box::new(cse)))
            }
            None => self.parent.clone().read_body(self.id),
        }
    }

    fn search(
        self: Arc<Self>,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    > {
        let logger = self.parent.clone().config().logger();
        match kind.as_deref() {
            Some(b"credential") | None => (),
            _ => return Ok(Box::new(Vec::new().into_iter())),
        }
        let g = self.credential.lock().unwrap();
        let csse: Option<&CredentialStoreSearchElement> = match (
            pattern.map(|p| p.downcast_ref::<CredentialStoreSearchElement>()),
            g.as_ref(),
        ) {
            (Some(Some(p)), _) => Some(p),
            (None, Some(_)) => None,
            _ => return Err(ResponseCode::NotSupported.into()),
        };
        if g.is_some() {
            return Ok(Box::new(vec![self.clone().to_store_element()].into_iter()));
        }
        match recurse {
            StoreSearchRecursionLevel::Boolean(true) => (),
            StoreSearchRecursionLevel::Boolean(false) => return Ok(Box::new(vec![].into_iter())),
            _ => return Err(ResponseCode::NotSupported.into()),
        }
        std::mem::drop(g);
        let req = match csse.and_then(|req| req.try_into().ok()) {
            Some(req) => req,
            None => return Ok(Box::new(vec![].into_iter())),
        };
        trace!(logger, "server: credential: search: {:?}", req);
        match self.parent.clone().search_credential(self.id(), &req) {
            Ok(Some((cred, path))) => {
                let elem = Arc::new(CommandCredentialBackendHandle {
                    store_id: self.store_id,
                    id: self.parent.clone().next_id(),
                    path,
                    credential: Mutex::new(Some(cred)),
                    parent: self.parent.clone(),
                });
                self.parent.clone().insert_handle(elem.id, elem.clone());
                Ok(Box::new(vec![elem.to_store_element()].into_iter()))
            }
            Ok(None) => {
                trace!(logger, "server: credential: no credential returned");
                Ok(Box::new(vec![].into_iter()))
            }
            Err(CredentialParserError::Unauthenticated) => {
                trace!(
                    logger,
                    "server: credential: unauthenticated reading credential",
                );
                Err(ResponseCode::NeedsAuthentication.into())
            }
            Err(e) => {
                trace!(
                    logger,
                    "server: credential: error reading credential: {:?}",
                    e
                );
                Ok(Box::new(vec![].into_iter()))
            }
        }
    }

    fn create(
        self: Arc<Self>,
        path: Option<Bytes>,
        kind: &str,
        _meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        let logger = self.parent.clone().config().logger();
        trace!(
            logger,
            "server: creating element of type {} with path {:?}",
            kind,
            path
        );
        if let Some(path) = path {
            if kind != "directory" {
                trace!(
                    logger,
                    "server: attempting to create unsupported object {} by name",
                    kind
                );
                return Err(ResponseCode::NotSupported.into());
            }
            trace!(logger, "server: creating directory");
            match self.parent.clone().create_directory(path.clone()) {
                Ok(()) => {
                    let handle = Arc::new(CommandCredentialBackendHandle {
                        store_id: self.store_id,
                        id: self.parent.clone().next_id(),
                        path,
                        credential: Mutex::new(None),
                        parent: self.parent.clone(),
                    });
                    self.parent.clone().insert_handle(handle.id, handle.clone());
                    return Ok(handle.to_store_element());
                }
                Err(e) => return Err(e),
            }
        }
        if kind != "credential" {
            trace!(
                logger,
                "server: attempting to create unsupported non-credential object {}",
                kind
            );
            return Err(ResponseCode::NotSupported.into());
        }
        trace!(logger, "server: creating credential");
        let c: &CredentialStoreElement =
            match body.and_then(|p| p.downcast_ref::<CredentialStoreElement>()) {
                Some(p) => p,
                None => return Err(ResponseCode::NotSupported.into()),
            };
        let mut c: Credential = c.try_into().map_err(|e| {
            trace!(logger, "server: failed to convert credential: {}", e);
            protocol::Error::from(ResponseCode::Invalid)
        })?;
        c.id = c.generate_id();
        // TODO: use a better error code.
        let path = self
            .parent
            .clone()
            .write_credential(self.id(), &c, false, true)
            .map_err(|e| match e {
                CredentialParserError::Unauthenticated => ResponseCode::NeedsAuthentication.into(),
                e => {
                    let logger = self.parent.clone().config().logger();
                    trace!(
                        logger,
                        "server: {} credential: update: error: {}",
                        self.parent.backend_type(),
                        e
                    );
                    protocol::Error::from(ResponseCode::InternalError)
                }
            })?;
        let handle = Arc::new(CommandCredentialBackendHandle {
            store_id: self.store_id,
            id: self.parent.clone().next_id(),
            path,
            credential: Mutex::new(Some(c)),
            parent: self.parent.clone(),
        });
        self.parent.clone().insert_handle(handle.id, handle.clone());
        Ok(handle.to_store_element())
    }

    fn contents(
        &self,
    ) -> Result<
        Option<Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>>,
        protocol::Error,
    > {
        let logger = self.parent.clone().config().logger();
        let kind = CredentialPathComponentType::from_path(self.path.clone())
            .ok_or(ResponseCode::InternalError)?;
        trace!(
            logger,
            "server: {} backend: contents: list contents: {:?}",
            self.parent.backend_type(),
            kind,
        );
        if kind == CredentialPathComponentType::Backend {
            match self.parent.clone().list_vaults() {
                Ok(vaults) => {
                    let store_id = self.store_id;
                    let parent = self.parent.clone();
                    let backend = self.backend_name();
                    let v = vaults
                        .iter()
                        .map(|v| {
                            let path = format_bytes!(b"/{}/{}/", backend, v.as_ref());
                            let handle = Arc::new(CommandCredentialBackendHandle {
                                store_id,
                                id: parent.clone().next_id(),
                                path: path.into(),
                                credential: Mutex::new(None),
                                parent: parent.clone(),
                            });
                            parent.clone().insert_handle(handle.id, handle.clone());
                            handle.to_store_element_entry()
                        })
                        .collect::<Vec<_>>();
                    Ok(Some(Box::new(v.into_iter())))
                }
                Err(CredentialParserError::Unauthenticated) => {
                    Err(ResponseCode::NeedsAuthentication.into())
                }
                Err(_) => Err(ResponseCode::InternalError.into()),
            }
        } else {
            match self.parent.clone().list_entries(self.id) {
                Ok(Some(b)) => {
                    let v = b.map(|h| h.to_store_element_entry()).collect::<Vec<_>>();
                    Ok(Some(Box::new(v.into_iter())))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }
}

pub(super) type BoxedCredentialBackendHandleIterator =
    Box<dyn Iterator<Item = Arc<dyn CredentialBackendHandle + Send + Sync>> + Send + Sync>;

pub trait CommandCredentialBackend {
    type Backend: Send + Sync;

    fn config(self: Arc<Self>) -> Arc<Config>;
    fn backend_name(&self) -> &[u8];
    fn backend_type(&self) -> &str;
    fn list_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError>;
    fn listable(&self) -> bool;
    fn next_id(self: Arc<Self>) -> StoreSelectorID;
    fn needs_authentication(&self) -> bool;
    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata>;
    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error>;
    fn insert_handle(
        self: Arc<Self>,
        id: StoreSelectorID,
        handle: Arc<dyn CredentialBackendHandle + Send + Sync>,
    );
    fn get_handle(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Option<Arc<dyn CredentialBackendHandle + Send + Sync>>;
    fn search_credential(
        self: Arc<Self>,
        id: StoreSelectorID,
        cred: &CredentialRequest,
    ) -> Result<Option<(Credential, Bytes)>, CredentialParserError>;
    fn write_credential(
        self: Arc<Self>,
        id: StoreSelectorID,
        cred: &Credential,
        overwrite: bool,
        create: bool,
    ) -> Result<Bytes, CredentialParserError>;
    fn delete_credential(
        self: Arc<Self>,
        id: StoreSelectorID,
        cred: &Credential,
    ) -> Result<(), CredentialParserError>;
    fn delete_credential_by_id(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<(), CredentialParserError>;
    fn list_entries(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<Option<BoxedCredentialBackendHandleIterator>, protocol::Error>;
    fn exists(self: Arc<Self>, path: Bytes) -> Result<bool, CredentialParserError>;
    fn read_body(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error>;
    fn create_directory(self: Arc<Self>, path: Bytes) -> Result<(), protocol::Error>;
}

impl<
        T: Send + Sync + 'static,
        U: CommandCredentialBackend<Backend = T> + Send + Sync + 'static,
    > CredentialBackend for U
{
    fn name(&self) -> &[u8] {
        self.backend_name()
    }

    fn vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError> {
        self.list_vaults()
    }

    fn vault_by_name(
        self: Arc<Self>,
        store_id: StoreID,
        name: &[u8],
    ) -> Result<Option<Arc<dyn CredentialVault + Send + Sync>>, CredentialParserError> {
        if self.list_vaults()?.iter().any(|nm| *nm == name) {
            let vault = Arc::new(CommandCredentialVault {
                store_id,
                id: self.clone().next_id(),
                name: Bytes::copy_from_slice(name),
                parent: self.clone(),
            });
            self.insert_handle(vault.id, vault.clone().to_handle());
            Ok(Some(vault))
        } else {
            Ok(None)
        }
    }

    fn next_handle(
        self: Arc<Self>,
        store_id: StoreID,
        path: Bytes,
    ) -> Arc<dyn CredentialBackendHandle + Send + Sync> {
        let id = self.clone().next_id();

        let handle = Arc::new(CommandCredentialBackendHandle {
            store_id,
            id,
            parent: self.clone(),
            path,
            credential: Mutex::new(None),
        });
        self.insert_handle(id, handle.clone());
        handle
    }

    fn handle_from_id(
        self: Arc<Self>,
        _store_id: StoreID,
        id: StoreSelectorID,
    ) -> Option<Arc<dyn CredentialBackendHandle + Send + Sync>> {
        self.get_handle(id)
    }

    fn to_handle(
        self: Arc<Self>,
        store_id: StoreID,
    ) -> Arc<dyn CredentialBackendHandle + Send + Sync> {
        let path = StorePath::from_components::<&[u8]>(&[b"", self.backend_name(), b""]).unwrap();
        self.next_handle(store_id, path.into_inner())
    }

    fn acquire_at_path(
        self: Arc<Self>,
        store_id: StoreID,
        path: Bytes,
    ) -> Result<Option<Arc<dyn CredentialBackendHandle + Send + Sync>>, CredentialParserError> {
        if self.clone().exists(path.clone())? {
            Ok(Some(self.next_handle(store_id, path)))
        } else {
            Ok(None)
        }
    }

    fn needs_authentication(&self) -> Option<bool> {
        Some(CommandCredentialBackend::needs_authentication(self))
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        CommandCredentialBackend::authentication_metadata(self)
    }
}
