use super::{
    BoxedStoreElementEntryIterator, PlainStoreElementEntry, Store, StoreAuthenticationMetadata,
    StoreElement, StoreElementEntry, StoreElementEntryIterator, StorePath,
    StoreSearchRecursionLevel,
};
use crate::config::{Config, CredentialBackendType};
use crate::credential::CredentialParserError;
use crate::server::SharedServerState;
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_protocol::protocol::{
    self, CredentialStoreElement, ResponseCode, StoreID, StoreSelectorID,
};
use serde_cbor::Value;
use std::any::Any;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub mod git;
pub mod helpers;
pub mod memory;

pub trait CredentialBackend {
    fn name(&self) -> &[u8];
    fn vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError>;
    fn vault_by_name(
        self: Arc<Self>,
        store_id: StoreID,
        name: &[u8],
    ) -> Result<Option<Arc<dyn CredentialVault + Send + Sync>>, CredentialParserError>;
    fn next_handle(
        self: Arc<Self>,
        store_id: StoreID,
        path: Bytes,
    ) -> Arc<dyn CredentialBackendHandle + Send + Sync>;
    fn handle_from_id(
        self: Arc<Self>,
        store_id: StoreID,
        id: StoreSelectorID,
    ) -> Option<Arc<dyn CredentialBackendHandle + Send + Sync>>;
    fn to_handle(
        self: Arc<Self>,
        store_id: StoreID,
    ) -> Arc<dyn CredentialBackendHandle + Send + Sync>;
    fn acquire_at_path(
        self: Arc<Self>,
        store_id: StoreID,
        path: Bytes,
    ) -> Result<Option<Arc<dyn CredentialBackendHandle + Send + Sync>>, CredentialParserError>;
    fn needs_authentication(&self) -> Option<bool>;
    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata>;
}

pub trait CredentialBackendHandle {
    fn config(&self) -> Arc<Config>;
    fn store_id(&self) -> StoreID;
    fn id(&self) -> StoreSelectorID;
    fn to_store_element_entry(self: Arc<Self>) -> Arc<dyn StoreElementEntry + Send + Sync>;
    fn to_store_element(self: Arc<Self>) -> Arc<dyn StoreElement + Send + Sync>;
    fn backend_name(&self) -> &[u8];
    fn backend_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError>;
    fn needs_authentication(&self) -> Option<bool>;
    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata>;
    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error>;
    fn update(
        self: Arc<Self>,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<(), protocol::Error>;
    fn delete(&self) -> Result<(), protocol::Error>;
    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>>;
    fn body(&self) -> Result<Option<Box<(dyn Any + Send + Sync + 'static)>>, protocol::Error>;
    fn create(
        self: Arc<Self>,
        path: Option<Bytes>,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error>;
    fn search(
        self: Arc<Self>,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    >;
    fn contents(&self) -> Result<Option<BoxedStoreElementEntryIterator>, protocol::Error>;
}

#[derive(Clone)]
struct TopLevelCredentialBackendHandle {
    store_id: StoreID,
    id: StoreSelectorID,
    config: Arc<Config>,
    backends: Arc<Mutex<BTreeMap<Bytes, Arc<dyn CredentialBackend + Send + Sync>>>>,
    elems: CredentialElements,
}

impl StoreElement for TopLevelCredentialBackendHandle {
    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn id(&self) -> StoreSelectorID {
        self.id
    }

    fn path(&self) -> Bytes {
        Bytes::from(b"/" as &[u8])
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
        CredentialBackendHandle::contents(self)
    }

    fn needs_authentication(&self) -> Option<bool> {
        CredentialBackendHandle::needs_authentication(self)
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        CredentialBackendHandle::authentication_metadata(self)
    }

    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error> {
        CredentialBackendHandle::authenticate(self, kind, message)
    }

    fn update(
        self: Arc<Self>,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<(), protocol::Error> {
        CredentialBackendHandle::update(self, meta, body)
    }

    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>> {
        CredentialBackendHandle::meta(self)
    }

    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error> {
        CredentialBackendHandle::body(self)
    }

    fn delete(&self) -> Result<(), protocol::Error> {
        CredentialBackendHandle::delete(self)
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
        CredentialBackendHandle::search(self, kind, pattern, recurse)
    }

    fn create(
        self: Arc<Self>,
        path: Option<Bytes>,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        CredentialBackendHandle::create(self, path, kind, meta, body)
    }
}

impl CredentialBackendHandle for TopLevelCredentialBackendHandle {
    fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn id(&self) -> StoreSelectorID {
        self.id
    }

    fn to_store_element_entry(self: Arc<Self>) -> Arc<dyn StoreElementEntry + Send + Sync> {
        Arc::new(Self {
            store_id: self.store_id,
            id: self.id,
            config: self.config.clone(),
            backends: self.backends.clone(),
            elems: self.elems.clone(),
        })
    }

    fn to_store_element(self: Arc<Self>) -> Arc<dyn StoreElement + Send + Sync> {
        Arc::new(Self {
            store_id: self.store_id,
            id: self.id,
            config: self.config.clone(),
            backends: self.backends.clone(),
            elems: self.elems.clone(),
        })
    }

    fn backend_name(&self) -> &[u8] {
        // TODO: make into an Option.
        &[]
    }

    fn backend_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError> {
        // TODO: make into an Option.
        Ok(Cow::Borrowed(&[]))
    }

    fn needs_authentication(&self) -> Option<bool> {
        Some(false)
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

    fn update(
        self: Arc<Self>,
        _meta: Option<&BTreeMap<Bytes, Value>>,
        _body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<(), protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn delete(&self) -> Result<(), protocol::Error> {
        Err(ResponseCode::NotSupported.into())
    }

    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>> {
        None
    }

    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error> {
        Ok(None)
    }

    fn search(
        self: Arc<Self>,
        _kind: Option<Bytes>,
        _pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        _recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    > {
        Err(ResponseCode::NotSupported.into())
    }

    fn create(
        self: Arc<Self>,
        _path: Option<Bytes>,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        let logger = self.config.logger();
        if kind != "credential" {
            return Err(ResponseCode::NotSupported.into());
        }
        let location = match self.clone().credential_location(body, b"create-location")? {
            Some(location) => location.into(),
            None => return Err(ResponseCode::NotFound.into()),
        };
        trace!(logger, "credential: desired location for /: {:?}", location);
        let obj = match CredentialStore::acquire_child(
            self.store_id,
            location,
            self.backends.clone(),
            self.elems.clone(),
        )? {
            Some(obj) => obj,
            None => return Err(ResponseCode::NotFound.into()),
        };
        obj.create(None, kind, meta, body)
    }

    fn contents(
        &self,
    ) -> Result<
        Option<Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>>,
        protocol::Error,
    > {
        let backends = self.backends.lock().unwrap();
        Ok(Some(Box::new(StoreElementEntryIterator::new(
            backends
                .iter()
                .map(|(name, backend)| {
                    let e: Arc<dyn StoreElementEntry + Send + Sync> =
                        Arc::new(PlainStoreElementEntry {
                            store_id: self.store_id,
                            path: format_bytes!(b"/{}/", name.as_ref()).into(),
                            kind: Bytes::from(b"directory" as &[u8]),
                            auth: backend.needs_authentication(),
                            auth_meta: backend.authentication_metadata(),
                        });
                    e
                })
                .collect(),
        ))))
    }
}

impl TopLevelCredentialBackendHandle {
    fn credential_location(
        self: Arc<Self>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
        kind: &'static [u8],
    ) -> Result<Option<String>, protocol::Error> {
        let logger = self.config.logger();
        let c: &CredentialStoreElement =
            match body.and_then(|p| p.downcast_ref::<CredentialStoreElement>()) {
                Some(p) => p,
                None => return Err(ResponseCode::NotSupported.into()),
            };
        let args: Arc<[Bytes]> = Arc::new([Bytes::from(kind)]);
        let result = self
            .clone()
            .config
            .credential_backend_control(args, Some(c));
        trace!(logger, "credential: finding location for /: {:?}", result);
        result.map_err(|_| ResponseCode::NotSupported.into())
    }
}

pub struct CredentialBackendStoreElement<T: CredentialBackendHandle> {
    store_id: StoreID,
    id: StoreSelectorID,
    path: Bytes,
    parent: Arc<T>,
}

impl<T: CredentialBackendHandle> StoreElement for CredentialBackendStoreElement<T> {
    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn id(&self) -> StoreSelectorID {
        self.id
    }

    fn path(&self) -> Bytes {
        self.path.clone()
    }

    fn is_directory(&self) -> bool {
        self.path.ends_with(b"/")
    }

    fn kind(&self) -> &[u8] {
        if StoreElement::is_directory(self) {
            b"directory"
        } else {
            b"credential"
        }
    }

    fn contents(
        &self,
    ) -> Result<
        Option<Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>>,
        protocol::Error,
    > {
        if !StoreElement::is_directory(self) {
            return Ok(None);
        }
        self.parent.clone().contents()
    }

    fn needs_authentication(&self) -> Option<bool> {
        self.parent.needs_authentication()
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
        self.parent.clone().update(meta, body)
    }

    fn delete(&self) -> Result<(), protocol::Error> {
        self.parent.delete()
    }

    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>> {
        None
    }

    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error> {
        self.parent.body()
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
        self.parent.clone().search(kind, pattern, recurse)
    }

    fn create(
        self: Arc<Self>,
        path: Option<Bytes>,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        self.parent.clone().create(path, kind, meta, body)
    }
}

pub trait CredentialVault: StoreElement {
    fn name(&self) -> &[u8];
    fn search(
        self: Arc<Self>,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    >;
    fn to_handle(self: Arc<Self>) -> Arc<dyn CredentialBackendHandle + Send + Sync>;
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CredentialPathComponentType {
    Top,
    Backend,
    Vault,
    VaultDirectory,
    Entry,
}

impl CredentialPathComponentType {
    pub fn from_path(path: Bytes) -> Option<Self> {
        if !path.starts_with(b"/") {
            return None;
        }
        let len = path.iter().cloned().filter(|x| *x == b'/').count();
        Self::from_component_data(len + 1, path.ends_with(b"/"))
    }

    fn from_path_components<T: AsRef<[u8]>>(components: &[T]) -> Option<Self> {
        if components.len() < 2 || !components[0].as_ref().is_empty() {
            // This should never occur.
            return None;
        }
        Self::from_component_data(
            components.len(),
            components[components.len() - 1].as_ref().is_empty(),
        )
    }

    fn from_component_data(len: usize, last_is_empty: bool) -> Option<Self> {
        match (len, last_is_empty) {
            // This is the top-level item.
            (2, true) => Some(CredentialPathComponentType::Top),
            // This is trying to use a credential backend as a file.
            (2, false) => None,
            // This is a credential backend.
            (3, true) => Some(CredentialPathComponentType::Backend),
            // This is trying to use a credential vault as a file.
            (3, false) => None,
            // This is a credential vault.
            (4, true) => Some(CredentialPathComponentType::Vault),
            // This is a credential vault directory.
            (n, true) if n >= 5 => Some(CredentialPathComponentType::VaultDirectory),
            // This is a credential vault entry.
            (n, false) if n >= 4 => Some(CredentialPathComponentType::Entry),
            _ => None,
        }
    }
}

type CredentialElements =
    Arc<RwLock<BTreeMap<StoreSelectorID, Arc<dyn CredentialBackendHandle + Send + Sync>>>>;

pub struct CredentialStore {
    id: StoreID,
    config: Arc<Config>,
    next_id: Arc<AtomicU32>,
    elems: CredentialElements,
    backends: Arc<Mutex<BTreeMap<Bytes, Arc<dyn CredentialBackend + Send + Sync>>>>,
    shared_state: Arc<SharedServerState>,
}

impl CredentialStore {
    pub fn new(id: StoreID, config: Arc<Config>, shared_state: Arc<SharedServerState>) -> Self {
        Self {
            id,
            elems: Arc::new(RwLock::new(BTreeMap::new())),
            next_id: Arc::new(AtomicU32::new(0)),
            config,
            backends: Arc::new(Mutex::new(BTreeMap::new())),
            shared_state,
        }
    }

    fn create_all_backends(&self) {
        if let Ok(backends) = self.config.credential_backends_as_map() {
            for (name, _) in backends {
                self.create_backend_from_name(name.as_bytes());
            }
        }
    }

    fn create_backend_from_name(
        &self,
        name: &[u8],
    ) -> Option<Arc<dyn CredentialBackend + Send + Sync>> {
        let mut data = self.backends.lock().unwrap();
        if let Some(backend) = data.get(name) {
            return Some(backend.clone());
        }
        let backends = self.config.credential_backends_as_map().ok()?;
        let backend = std::str::from_utf8(name).ok().and_then(|c| backends.get(c));
        let obj: Option<Arc<dyn CredentialBackend + Send + Sync>> =
            match backend.as_ref().map(|b| &b.kind) {
                Some(CredentialBackendType::Git { command }) => {
                    Some(Arc::new(git::GitCredentialBackend::new(
                        self.config.clone(),
                        self.elems.clone(),
                        self.next_id.clone(),
                        Bytes::copy_from_slice(name),
                        &command,
                    )))
                }
                Some(CredentialBackendType::Memory { token }) => {
                    Some(Arc::new(memory::MemoryCredentialBackend::new(
                        self.config.clone(),
                        self.elems.clone(),
                        self.next_id.clone(),
                        Bytes::copy_from_slice(name),
                        token.as_deref(),
                        self.shared_state.clone(),
                    )))
                }
                _ => None,
            };
        let obj = obj?;
        data.insert(Bytes::copy_from_slice(name), obj.clone());
        Some(obj)
    }

    fn acquire_child(
        id: StoreID,
        path: Bytes,
        backends: Arc<Mutex<BTreeMap<Bytes, Arc<dyn CredentialBackend + Send + Sync>>>>,
        elems: CredentialElements,
    ) -> Result<Option<Arc<dyn StoreElement + Send + Sync>>, protocol::Error> {
        let components: Vec<_> = match StorePath::new(path.clone()) {
            Some(p) => p.components(),
            None => return Err(ResponseCode::NotFound.into()),
        };
        if components.len() < 2 || !components[0].is_empty() {
            // This should never occur.
            return Err(ResponseCode::NotFound.into());
        }
        let be = backends.lock().unwrap();
        let backend = components
            .get(1)
            .and_then(|c| be.get(c))
            .ok_or(ResponseCode::NotFound)?;
        let resp: Result<Option<Arc<dyn CredentialBackendHandle + Send + Sync>>, _> =
            match CredentialPathComponentType::from_path_components(&components) {
                Some(CredentialPathComponentType::Vault) => {
                    let vault = components
                        .get(2)
                        .and_then(|v| backend.clone().vault_by_name(id, v).ok()?)
                        .ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                    Ok(Some(vault.to_handle()))
                }
                Some(CredentialPathComponentType::VaultDirectory)
                | Some(CredentialPathComponentType::Entry) => backend
                    .clone()
                    .acquire_at_path(id, path)
                    .map_err(|e| match e {
                        CredentialParserError::Unlistable => ResponseCode::Unlistable.into(),
                        CredentialParserError::Unauthenticated => {
                            ResponseCode::NeedsAuthentication.into()
                        }
                        CredentialParserError::NoSuchHandle => ResponseCode::NotFound.into(),
                        _ => ResponseCode::InternalError.into(),
                    }),
                _ => Err(ResponseCode::NotFound.into()),
            };
        if let Ok(Some(ref item)) = resp {
            elems.write().unwrap().insert(item.id(), item.clone());
        }
        resp.map(|op| op.map(|el| el.to_store_element()))
    }
}

impl Store for CredentialStore {
    fn id(&self) -> StoreID {
        self.id
    }

    fn acquire(
        &self,
        path: Bytes,
    ) -> Result<Option<Arc<dyn StoreElement + Send + Sync>>, protocol::Error> {
        let components: Vec<_> = match StorePath::new(path.clone()) {
            Some(p) => p.components(),
            None => return Err(ResponseCode::NotFound.into()),
        };
        if components.len() < 2 || !components[0].is_empty() {
            // This should never occur.
            return Err(ResponseCode::NotFound.into());
        }
        let backend = components
            .get(1)
            .and_then(|c| self.create_backend_from_name(c));
        let resp: Result<Option<Arc<dyn CredentialBackendHandle + Send + Sync>>, _> =
            match CredentialPathComponentType::from_path_components(&components) {
                Some(CredentialPathComponentType::Top) => {
                    self.create_all_backends();
                    Ok(Some(Arc::new(TopLevelCredentialBackendHandle {
                        store_id: self.id,
                        id: StoreSelectorID(self.next_id.fetch_add(1, Ordering::AcqRel)),
                        config: self.config.clone(),
                        backends: self.backends.clone(),
                        elems: self.elems.clone(),
                    })))
                }
                Some(CredentialPathComponentType::Backend) => match backend {
                    Some(b) => Ok(Some(b.to_handle(self.id()))),
                    None => Err(ResponseCode::NotFound.into()),
                },
                Some(CredentialPathComponentType::Vault) => {
                    let b = backend.ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                    let vault = components
                        .get(2)
                        .and_then(|v| b.vault_by_name(self.id, v).ok()?)
                        .ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                    Ok(Some(vault.to_handle()))
                }
                Some(CredentialPathComponentType::VaultDirectory)
                | Some(CredentialPathComponentType::Entry) => {
                    let b = backend.ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                    b.acquire_at_path(self.id, path).map_err(|e| match e {
                        CredentialParserError::Unlistable => ResponseCode::Unlistable.into(),
                        CredentialParserError::Unauthenticated => {
                            ResponseCode::NeedsAuthentication.into()
                        }
                        CredentialParserError::NoSuchHandle => ResponseCode::NotFound.into(),
                        _ => ResponseCode::InternalError.into(),
                    })
                }
                None => Err(ResponseCode::NotFound.into()),
            };
        if let Ok(Some(ref item)) = resp {
            self.elems.write().unwrap().insert(item.id(), item.clone());
        }
        resp.map(|op| op.map(|el| el.to_store_element()))
    }

    fn get(&self, id: StoreSelectorID) -> Option<Arc<dyn StoreElement + Send + Sync>> {
        self.elems
            .read()
            .unwrap()
            .get(&id)
            .map(|handle| handle.clone().to_store_element())
    }

    fn close(&self, id: StoreSelectorID) -> Result<(), protocol::Error> {
        match self.elems.write().unwrap().remove(&id) {
            Some(_) => Ok(()),
            None => Err(ResponseCode::NotFound.into()),
        }
    }

    fn delete(&self, id: StoreSelectorID) -> Result<(), protocol::Error> {
        let resp = match self.elems.read().unwrap().get(&id) {
            Some(handle) => handle.delete(),
            None => Err(ResponseCode::NotFound.into()),
        };
        let _ = self.close(id);
        resp
    }

    fn search(
        &self,
        id: StoreSelectorID,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    > {
        match self.elems.read().unwrap().get(&id) {
            Some(handle) => handle.clone().search(kind, pattern, recurse),
            None => Err(ResponseCode::NotFound.into()),
        }
    }

    fn create(
        &self,
        path: Bytes,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error> {
        match (path.ends_with(b"/"), kind) {
            (true, "directory") => {
                let mut components = StorePath::new(path.clone())
                    .ok_or(ResponseCode::Invalid)?
                    .components();
                if components.len() < 3 {
                    return Err(ResponseCode::Invalid.into());
                }
                components.remove(components.len() - 2);
                let newpath = StorePath::from_components(&components)
                    .ok_or(ResponseCode::Invalid)?
                    .into_inner();
                let handle = self
                    .acquire(newpath)?
                    .ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                handle.create(Some(path), kind, meta, body)
            }
            // We're creating an element at a location that's specified by the backend.
            (true, _) => {
                let handle = self
                    .acquire(path)?
                    .ok_or(protocol::Error::from(ResponseCode::NotFound))?;
                handle.create(None, kind, meta, body)
            }
            _ => Err(ResponseCode::NotSupported.into()),
        }
    }
}
