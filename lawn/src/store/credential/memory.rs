use super::helpers::{
    BoxedCredentialBackendHandleIterator, CommandCredentialBackend, CommandCredentialBackendHandle,
};
use super::{CredentialBackendHandle, CredentialElements, CredentialPathComponentType};
use crate::config::Config;
use crate::credential::{Credential, CredentialParserError, CredentialRequest};
use crate::server::SharedServerState;
use crate::store::{StoreAuthenticationMetadata, StorePath};
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_constants::logger::AsLogStr;
use lawn_protocol::protocol::{
    self, CredentialStoreElement, KeyboardInteractiveAuthenticationPrompt,
    KeyboardInteractiveAuthenticationRequest, KeyboardInteractiveAuthenticationResponse,
    ResponseCode, StoreSelectorID,
};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use subtle::ConstantTimeEq;

trait VaultContainer {
    fn entry(&self, name: &[u8]) -> Option<&VaultEntry>;
    fn entry_mut(&mut self, name: &[u8]) -> Option<&mut VaultEntry>;
    fn entries(&self) -> &BTreeMap<Bytes, VaultEntry>;
    fn entries_mut(&mut self) -> &mut BTreeMap<Bytes, VaultEntry>;
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct VaultDirectory {
    entries: BTreeMap<Bytes, VaultEntry>,
}

impl VaultDirectory {
    fn new() -> Self {
        Default::default()
    }
}

impl VaultContainer for VaultDirectory {
    fn entry(&self, name: &[u8]) -> Option<&VaultEntry> {
        self.entries.get(name)
    }

    fn entry_mut(&mut self, name: &[u8]) -> Option<&mut VaultEntry> {
        self.entries.get_mut(name)
    }

    fn entries(&self) -> &BTreeMap<Bytes, VaultEntry> {
        &self.entries
    }

    fn entries_mut(&mut self) -> &mut BTreeMap<Bytes, VaultEntry> {
        &mut self.entries
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum VaultEntry {
    Credential(Credential),
    Directory(VaultDirectory),
}

#[derive(Default, Serialize, Deserialize)]
pub(super) struct Vault {
    entries: BTreeMap<Bytes, VaultEntry>,
}

impl Vault {
    fn new() -> Self {
        Default::default()
    }
}

impl VaultContainer for Vault {
    fn entry(&self, name: &[u8]) -> Option<&VaultEntry> {
        self.entries.get(name)
    }

    fn entry_mut(&mut self, name: &[u8]) -> Option<&mut VaultEntry> {
        self.entries.get_mut(name)
    }

    fn entries(&self) -> &BTreeMap<Bytes, VaultEntry> {
        &self.entries
    }

    fn entries_mut(&mut self) -> &mut BTreeMap<Bytes, VaultEntry> {
        &mut self.entries
    }
}

#[derive(Debug, Copy, Clone)]
enum AuthenticationState {
    Start,
    SentKeyboardInteractivePrompt,
    Authenticated,
}

impl Default for AuthenticationState {
    fn default() -> Self {
        Self::Start
    }
}

pub(super) struct LockableData {
    locked: AtomicBool,
    auth_state: Mutex<AuthenticationState>,
    vaults: RwLock<BTreeMap<Bytes, Vault>>,
}

impl LockableData {
    fn new(locked: bool) -> Self {
        Self {
            locked: AtomicBool::new(locked),
            auth_state: Mutex::new(AuthenticationState::Start),
            vaults: RwLock::new(BTreeMap::new()),
        }
    }

    fn vaults(&self) -> Option<&RwLock<BTreeMap<Bytes, Vault>>> {
        if self.locked.load(Ordering::SeqCst) {
            None
        } else {
            Some(&self.vaults)
        }
    }

    fn state_as_string(&self) -> &str {
        if self.vaults().is_some() {
            "unlocked"
        } else {
            "locked"
        }
    }
}

pub struct MemoryCredentialBackend {
    config: Arc<Config>,
    name: Bytes,
    token: Option<String>,
    next_id: Arc<AtomicU32>,
    elems: CredentialElements,
    vaults: Arc<LockableData>,
}

impl MemoryCredentialBackend {
    pub fn new(
        config: Arc<Config>,
        elems: CredentialElements,
        ids: Arc<AtomicU32>,
        name: Bytes,
        token: Option<&str>,
        shared_state: Arc<SharedServerState>,
    ) -> Self {
        let st = shared_state;
        let key = Self::key_from_name(name.clone());
        let mut creds = st.credentials().write().unwrap();
        let logger = config.logger();
        let vaults = match creds.get(&key).cloned() {
            Some(v) => {
                trace!(logger, "server: memory backend: found cache entry");
                match v.downcast::<LockableData>().ok() {
                    Some(data) => {
                        trace!(
                            logger,
                            "server: memory backend: found cached data: locked {}",
                            data.locked.load(Ordering::Acquire)
                        );
                        Some(data)
                    }
                    None => {
                        trace!(logger, "server: memory backend: found unknown data");
                        None
                    }
                }
            }
            None => {
                trace!(
                    logger,
                    "server: memory backend: no cache entry; using default"
                );
                None
            }
        }
        .unwrap_or_else(|| Arc::new(LockableData::new(token.is_some())));
        creds.insert(key, vaults.clone());
        Self {
            config,
            name,
            next_id: ids,
            elems,
            token: token.map(|t| t.to_owned()),
            vaults,
        }
    }

    fn key_from_name(name: Bytes) -> Bytes {
        format_bytes!(b"credential:memory:storage:v1:{}", name.as_ref()).into()
    }

    fn components(&self, id: StoreSelectorID) -> Result<Vec<Bytes>, CredentialParserError> {
        let handle = self
            .elems
            .read()
            .unwrap()
            .get(&id)
            .ok_or(CredentialParserError::NoSuchHandle)?
            .clone();
        let elem = handle.clone().to_store_element();
        Ok(StorePath::new(elem.path()).unwrap().components())
    }

    fn container_from_components<'a>(
        &self,
        lock: &'a BTreeMap<Bytes, Vault>,
        components: &[Bytes],
    ) -> Result<Option<&'a dyn VaultContainer>, CredentialParserError> {
        let logger = self.config.logger();
        trace!(
            logger,
            "server: memory backend: container from components: {:?}",
            components
        );
        if components.len() <= 2 {
            return Ok(None);
        }
        let components = if components.last().map(|x| x.as_ref()) == Some(b"") {
            &components[0..components.len() - 1]
        } else {
            components
        };
        let mut entry: &dyn VaultContainer = match lock.get(&components[2]) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        if components.len() <= 3 {
            return Ok(Some(entry));
        }
        for component in &components[3..] {
            entry = match entry.entry(component) {
                Some(VaultEntry::Directory(entry)) => entry,
                Some(VaultEntry::Credential(_)) | None => return Ok(None),
            }
        }
        Ok(Some(entry))
    }

    fn container_mut_from_components<'a>(
        &self,
        lock: &'a mut BTreeMap<Bytes, Vault>,
        components: &[Bytes],
    ) -> Result<Option<&'a mut dyn VaultContainer>, CredentialParserError> {
        if components.len() <= 2 {
            return Ok(None);
        }
        let mut entry: &mut dyn VaultContainer = match lock.get_mut(&components[2]) {
            Some(entry) => entry,
            None => return Ok(None),
        };
        if components.len() <= 3 {
            return Ok(Some(entry));
        }
        for component in &components[3..] {
            entry = match entry.entry_mut(component) {
                Some(VaultEntry::Directory(entry)) => entry,
                Some(VaultEntry::Credential(_)) | None => return Ok(None),
            }
        }
        Ok(Some(entry))
    }

    fn container_for_id<'a>(
        &self,
        lock: &'a BTreeMap<Bytes, Vault>,
        id: StoreSelectorID,
    ) -> Result<Option<&'a dyn VaultContainer>, CredentialParserError> {
        let components = self.components(id)?;
        self.container_from_components(lock, &components)
    }

    fn parent_container_for_id<'a>(
        &self,
        lock: &'a BTreeMap<Bytes, Vault>,
        id: StoreSelectorID,
    ) -> Result<Option<(&'a dyn VaultContainer, Bytes)>, CredentialParserError> {
        let components = self.components(id)?;
        if components.len() <= 2 {
            return Ok(None);
        }
        let components = if components.last().map(|x| x.as_ref()) == Some(b"") {
            &components[0..components.len() - 1]
        } else {
            &components
        };
        match self.container_from_components(lock, &components[..components.len() - 1]) {
            Ok(Some(c)) => Ok(Some((c, components[components.len() - 1].clone()))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn parent_container_mut_for_id<'a>(
        &self,
        lock: &'a mut BTreeMap<Bytes, Vault>,
        id: StoreSelectorID,
    ) -> Result<Option<(&'a mut dyn VaultContainer, Bytes)>, CredentialParserError> {
        let components = self.components(id)?;
        if components.len() <= 2 {
            return Ok(None);
        }
        let components = if components.last().map(|x| x.as_ref()) == Some(b"") {
            &components[0..components.len() - 1]
        } else {
            &components
        };
        match self.container_mut_from_components(lock, &components[..components.len() - 1]) {
            Ok(Some(c)) => Ok(Some((c, components[components.len() - 1].clone()))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Returns the nearest containing directory for `id`, whether `id` itself or its parent.
    fn containing_directory<'a>(
        &self,
        lock: &'a mut BTreeMap<Bytes, Vault>,
        id: StoreSelectorID,
    ) -> Result<Option<(&'a mut dyn VaultContainer, Bytes, bool)>, CredentialParserError> {
        let components = self.components(id)?;
        if components.len() <= 2 {
            return Ok(None);
        }
        let (last, is_dir) = if components.last().map(|x| x.as_ref()) == Some(b"") {
            (components[components.len() - 2].clone(), true)
        } else {
            (components[components.len() - 1].clone(), false)
        };
        match self.container_mut_from_components(lock, &components[..components.len() - 1]) {
            Ok(Some(c)) => Ok(Some((c, last, is_dir))),
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn search_recursive(
        req: &CredentialRequest,
        container: &dyn VaultContainer,
        path: Bytes,
    ) -> Result<Option<(Credential, Bytes)>, CredentialParserError> {
        for (name, entry) in container.entries() {
            match entry {
                VaultEntry::Credential(c) if req.matches(c) => {
                    let path = format_bytes!(b"{}{}", path.as_ref(), name.as_ref());
                    return Ok(Some((c.clone(), path.into())));
                }
                VaultEntry::Credential(_) => continue,
                VaultEntry::Directory(d) => {
                    let path = format_bytes!(b"{}{}/", path.as_ref(), name.as_ref());
                    match Self::search_recursive(req, d, path.into()) {
                        Ok(Some(r)) => return Ok(Some(r)),
                        _ => continue,
                    }
                }
            }
        }
        Ok(None)
    }
}

impl CommandCredentialBackend for MemoryCredentialBackend {
    type Backend = Arc<Self>;

    fn config(self: Arc<Self>) -> Arc<Config> {
        self.config.clone()
    }

    fn backend_name(&self) -> &[u8] {
        self.name.as_ref()
    }

    fn backend_type(&self) -> &str {
        "memory"
    }

    fn needs_authentication(&self) -> bool {
        self.vaults.vaults().is_none()
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        if self.needs_authentication() {
            Some(StoreAuthenticationMetadata {
                methods: vec![
                    Bytes::from(b"PLAIN" as &[u8]),
                    Bytes::from(b"keyboard-interactive" as &[u8]),
                ],
            })
        } else {
            None
        }
    }

    fn authenticate(
        &self,
        kind: Bytes,
        message: Option<Bytes>,
    ) -> Result<(Option<Bytes>, bool), protocol::Error> {
        let logger = self.config.logger();
        let token = self
            .token
            .as_ref()
            .ok_or(protocol::Error::from(ResponseCode::NotSupported))?;
        let mut state = self.vaults.auth_state.lock().unwrap();
        trace!(
            logger,
            "server: memory credential: kind {}; state {:?}; message {:?}",
            kind.as_ref().as_log_str(),
            state,
            message,
        );
        let resp = match (kind.as_ref(), *state, message) {
            (_, AuthenticationState::Authenticated, _) => Err(ResponseCode::Conflict.into()),
            (b"keyboard-interactive", AuthenticationState::Start, None) => {
                let req = KeyboardInteractiveAuthenticationRequest {
                    name: "Password Authentication".into(),
                    instruction: "".into(),
                    prompts: vec![KeyboardInteractiveAuthenticationPrompt {
                        prompt: "Password".into(),
                        echo: false,
                    }],
                };
                *state = AuthenticationState::SentKeyboardInteractivePrompt;
                trace!(
                    logger,
                    "server: memory credential: keyboard-interactive auth start"
                );
                Ok((
                    Some(
                        serde_cbor::to_vec(&req)
                            .map_err(|_| protocol::Error::from(ResponseCode::AuthenticationFailed))?
                            .into(),
                    ),
                    true,
                ))
            }
            (b"keyboard-interactive", AuthenticationState::Start, Some(_)) => {
                Err(ResponseCode::Invalid.into())
            }
            (b"keyboard-interactive", AuthenticationState::SentKeyboardInteractivePrompt, None) => {
                Err(ResponseCode::Invalid.into())
            }
            (
                b"keyboard-interactive",
                AuthenticationState::SentKeyboardInteractivePrompt,
                Some(r),
            ) => {
                let req: KeyboardInteractiveAuthenticationResponse = serde_cbor::from_slice(&r)
                    .map_err(|_| protocol::Error::from(ResponseCode::AuthenticationFailed))?;
                if req.responses.len() == 1
                    && req.responses[0].as_bytes().ct_eq(token.as_bytes()).into()
                {
                    trace!(
                        logger,
                        "server: memory credential: keyboard-interactive auth ok"
                    );
                    *state = AuthenticationState::Authenticated;
                    self.vaults.locked.store(false, Ordering::SeqCst);
                    trace!(
                        logger,
                        "server: memory credential: vaults: {}",
                        self.vaults.state_as_string()
                    );
                    Ok((None, false))
                } else {
                    trace!(
                        logger,
                        "server: memory credential: keyboard-interactive auth failed"
                    );
                    Err(ResponseCode::AuthenticationFailed.into())
                }
            }
            (b"PLAIN", AuthenticationState::Start, None) => Err(ResponseCode::Invalid.into()),
            (b"PLAIN", AuthenticationState::Start, Some(msg)) => {
                let msg = std::str::from_utf8(&msg)
                    .map_err(|_| protocol::Error::from(ResponseCode::AuthenticationFailed))?;
                let values = msg.split(|x| u32::from(x) == 0).collect::<Vec<_>>();
                if values.len() != 3 {
                    return Err(ResponseCode::AuthenticationFailed.into());
                }
                if values[0].is_empty()
                    && values[1].is_empty()
                    && values[2].as_bytes().ct_eq(token.as_bytes()).into()
                {
                    trace!(logger, "server: memory credential: PLAIN auth ok");
                    *state = AuthenticationState::Authenticated;
                    self.vaults.locked.store(false, Ordering::SeqCst);
                    trace!(
                        logger,
                        "server: memory credential: vaults: {}",
                        self.vaults.state_as_string()
                    );
                    Ok((None, false))
                } else {
                    trace!(logger, "server: memory credential: PLAIN auth failed");
                    Err(ResponseCode::AuthenticationFailed.into())
                }
            }
            (_, _, _) => {
                trace!(logger, "server: memory credential: invalid message",);
                Err(ResponseCode::Invalid.into())
            }
        };
        if resp.is_err() {
            *state = AuthenticationState::Start;
        }
        resp
    }

    fn list_vaults(&self) -> Result<Cow<'_, [Bytes]>, CredentialParserError> {
        let logger = self.config.logger();
        trace!(
            logger,
            "server: memory credential: list vaults: vaults: {}",
            self.vaults.state_as_string()
        );
        let vaults = self
            .vaults
            .vaults()
            .ok_or(CredentialParserError::Unauthenticated)?
            .read()
            .unwrap();
        Ok(Cow::Owned(vaults.keys().cloned().collect()))
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
        id: StoreSelectorID,
        req: &CredentialRequest,
    ) -> Result<Option<(Credential, Bytes)>, CredentialParserError> {
        let vaults = self
            .vaults
            .vaults()
            .ok_or(CredentialParserError::Unauthenticated)?
            .read()
            .unwrap();
        let handle = self
            .elems
            .read()
            .unwrap()
            .get(&id)
            .ok_or(CredentialParserError::NoSuchHandle)?
            .clone();
        let elem = handle.clone().to_store_element();
        let container = match self.container_for_id(&vaults, id) {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        Self::search_recursive(req, container, elem.path())
    }

    fn write_credential(
        self: Arc<Self>,
        id: StoreSelectorID,
        cred: &Credential,
        overwrite: bool,
        create: bool,
    ) -> Result<Bytes, CredentialParserError> {
        let logger = self.clone().config().logger();
        let mut vaults = self
            .vaults
            .vaults()
            .ok_or(CredentialParserError::Unauthenticated)?
            .write()
            .unwrap();
        let handle = self
            .elems
            .read()
            .unwrap()
            .get(&id)
            .ok_or(CredentialParserError::NoSuchHandle)?
            .clone();
        let (container, component, is_dir) = match self.containing_directory(&mut vaults, id) {
            Ok(Some(c)) => c,
            Ok(None) => return Err(CredentialParserError::NoSuchHandle),
            Err(e) => return Err(e),
        };
        let last_item = if is_dir { cred.id.clone() } else { component };
        let entries = container.entries_mut();
        let mut components = StorePath::new(handle.to_store_element().path())
            .unwrap()
            .components();
        let last_idx = components.len() - 1;
        if components[last_idx].as_ref() == b"" {
            components[last_idx] = last_item.clone();
        }
        let path = StorePath::from_components(&components)
            .unwrap()
            .into_inner();
        trace!(
            logger,
            "server: memory backend: write credential: overwrite {}; create {}; entries {}, path {}",
            overwrite,
            create,
            entries.contains_key(&last_item),
            path.as_ref().as_log_str(),
        );
        match (overwrite, create, entries.entry(last_item)) {
            (true, _, Entry::Occupied(mut e)) => match (e.get_mut(), create) {
                (VaultEntry::Credential(ref mut c), _) => {
                    *c = cred.clone();
                    Ok(path)
                }
                (VaultEntry::Directory(d), true) => {
                    d.entries
                        .insert(cred.id(), VaultEntry::Credential(cred.clone()));
                    Ok(path)
                }
                (VaultEntry::Directory(_), false) => Err(CredentialParserError::NoSuchHandle),
            },
            (_, true, Entry::Vacant(e)) => {
                e.insert(VaultEntry::Credential(cred.clone()));
                Ok(path)
            }
            (_, _, _) => Err(CredentialParserError::NoSuchHandle),
        }
    }

    fn delete_credential(
        self: Arc<Self>,
        id: StoreSelectorID,
        _cred: &Credential,
    ) -> Result<(), CredentialParserError> {
        self.delete_credential_by_id(id)
    }

    fn delete_credential_by_id(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<(), CredentialParserError> {
        let mut vaults = self
            .vaults
            .vaults()
            .ok_or(CredentialParserError::Unauthenticated)?
            .write()
            .unwrap();
        let (container, component) = match self.parent_container_mut_for_id(&mut vaults, id) {
            Ok(Some(c)) => c,
            Ok(None) => return Err(CredentialParserError::NoSuchHandle),
            Err(e) => return Err(e),
        };
        let entries = container.entries_mut();
        match entries.remove(&component) {
            Some(_) => Ok(()),
            None => Err(CredentialParserError::NoSuchHandle),
        }
    }

    fn listable(&self) -> bool {
        false
    }

    fn list_entries(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<Option<BoxedCredentialBackendHandleIterator>, protocol::Error> {
        let logger = self.config.logger();
        trace!(
            logger,
            "server: memory credential: list entries: vaults: {}",
            self.vaults.state_as_string(),
        );
        let handle = self
            .elems
            .read()
            .unwrap()
            .get(&id)
            .ok_or(ResponseCode::NotFound)?
            .clone();
        let elem = handle.clone().to_store_element();
        trace!(
            logger,
            "server: memory credential: list entries: id {}: {}",
            id.0,
            elem.path().as_ref().as_log_str(),
        );
        let vaults = self
            .vaults
            .vaults()
            .ok_or(ResponseCode::NeedsAuthentication)?
            .write()
            .unwrap();
        let path = elem.path();
        let store_id = elem.store_id();
        if let Some(CredentialPathComponentType::Backend) =
            CredentialPathComponentType::from_path(elem.path())
        {
            let this = self.clone();
            let items: Vec<_> = vaults
                .keys()
                .map(|name| {
                    let mut components = StorePath::new(path.clone()).unwrap().components();
                    components.pop();
                    let handle: Arc<dyn CredentialBackendHandle + Send + Sync> = {
                        components.extend(
                            (&[name.clone(), Bytes::from(b"" as &[u8])] as &[Bytes])
                                .iter()
                                .cloned(),
                        );
                        let path = StorePath::from_components(&components)
                            .unwrap()
                            .into_inner();
                        Arc::new(CommandCredentialBackendHandle::new(
                            store_id,
                            id,
                            path,
                            this.clone(),
                        ))
                    };
                    this.clone().insert_handle(id, handle.clone());
                    handle
                })
                .collect();
            return Ok(Some(Box::new(items.into_iter())));
        }
        let container = match self.container_for_id(&vaults, id) {
            Ok(Some(c)) => c,
            Ok(None) => return Ok(None),
            Err(CredentialParserError::Unlistable) => return Err(ResponseCode::Unlistable.into()),
            Err(e) => {
                trace!(
                    logger,
                    "server: memory credential: list entries: error: {}",
                    e
                );
                return Err(ResponseCode::InternalError.into());
            }
        };
        if elem.kind() != b"directory" {
            return Err(ResponseCode::NotSupported.into());
        }
        let this = self.clone();
        let items: Vec<_> = container
            .entries()
            .iter()
            .map(move |(name, entry)| {
                let id = this.clone().next_id();
                let mut components = StorePath::new(path.clone()).unwrap().components();
                components.pop();
                let handle: Arc<dyn CredentialBackendHandle + Send + Sync> =
                    if let VaultEntry::Credential(c) = entry {
                        components.extend((&[name.clone()] as &[Bytes]).iter().cloned());
                        let path = StorePath::from_components(&components)
                            .unwrap()
                            .into_inner();
                        Arc::new(CommandCredentialBackendHandle::new_with_credential(
                            store_id,
                            id,
                            path,
                            this.clone(),
                            c.clone(),
                        ))
                    } else {
                        components.extend(
                            (&[name.clone(), Bytes::from(b"" as &[u8])] as &[Bytes])
                                .iter()
                                .cloned(),
                        );
                        let path = StorePath::from_components(&components)
                            .unwrap()
                            .into_inner();
                        Arc::new(CommandCredentialBackendHandle::new(
                            store_id,
                            id,
                            path,
                            this.clone(),
                        ))
                    };
                this.clone().insert_handle(id, handle.clone());
                handle
            })
            .collect();
        Ok(Some(Box::new(items.into_iter())))
    }

    fn create_directory(self: Arc<Self>, path: Bytes) -> Result<(), protocol::Error> {
        let logger = self.clone().config().logger();
        let components = StorePath::new(path.clone())
            .ok_or(ResponseCode::Invalid)?
            .components();
        let kind = CredentialPathComponentType::from_path_components(&components);
        trace!(
            logger,
            "server: creating directory at {} of kind {:?}",
            path.as_ref().as_log_str(),
            kind
        );
        match kind {
            Some(CredentialPathComponentType::Top)
            | Some(CredentialPathComponentType::Backend)
            | Some(CredentialPathComponentType::Entry) => Err(ResponseCode::NotSupported.into()),
            Some(CredentialPathComponentType::Vault) => {
                let vaults = self
                    .vaults
                    .vaults()
                    .ok_or(protocol::Error::from(ResponseCode::NeedsAuthentication))?;
                let mut vaults = vaults.write().unwrap();
                match vaults.entry(components[components.len() - 2].clone()) {
                    Entry::Occupied(_) => Err(ResponseCode::Conflict.into()),
                    Entry::Vacant(e) => {
                        e.insert(Vault::new());
                        Ok(())
                    }
                }
            }
            Some(CredentialPathComponentType::VaultDirectory) => {
                let vaults = self
                    .vaults
                    .vaults()
                    .ok_or(protocol::Error::from(ResponseCode::NeedsAuthentication))?;
                let mut vaults = vaults.write().unwrap();
                match self
                    .container_mut_from_components(&mut vaults, &components[..components.len() - 2])
                {
                    Ok(Some(c)) => {
                        c.entries_mut().insert(
                            components[components.len() - 2].clone(),
                            VaultEntry::Directory(VaultDirectory::new()),
                        );
                        Ok(())
                    }
                    Ok(None) => Err(ResponseCode::NotFound.into()),
                    Err(_) => Err(ResponseCode::InternalError.into()),
                }
            }
            None => Err(ResponseCode::Invalid.into()),
        }
    }

    fn exists(self: Arc<Self>, path: Bytes) -> Result<bool, CredentialParserError> {
        let vaults = self
            .vaults
            .vaults()
            .ok_or(CredentialParserError::Unauthenticated)?;
        let vaults = vaults.read().unwrap();
        let components = match StorePath::new(path) {
            Some(c) => c.components(),
            None => return Ok(false),
        };
        if components.len() <= 2 {
            return Ok(false);
        }
        let components = if components.last().map(|x| x.as_ref()) == Some(b"") {
            &components[0..components.len() - 1]
        } else {
            &components
        };
        let mut entry: &dyn VaultContainer = match vaults.get(&components[2]) {
            Some(entry) => entry,
            None => return Ok(false),
        };
        if components.len() <= 3 {
            return Ok(true);
        }
        let iterable = &components[3..];
        for (count, component) in iterable.iter().enumerate() {
            let is_last = iterable.is_empty() || count == iterable.len() - 1;
            entry = match entry.entry(component) {
                Some(VaultEntry::Directory(entry)) => entry,
                Some(VaultEntry::Credential(_)) => return Ok(is_last),
                None => return Ok(false),
            }
        }
        Ok(true)
    }

    fn read_body(
        self: Arc<Self>,
        id: StoreSelectorID,
    ) -> Result<Option<Box<dyn Any + 'static>>, protocol::Error> {
        let vaults = self
            .vaults
            .vaults()
            .ok_or(ResponseCode::NeedsAuthentication)?;
        let vaults = vaults.read().unwrap();
        let (cont, last) = self
            .parent_container_for_id(&vaults, id)
            .map_err(|_| ResponseCode::NotFound)?
            .ok_or(ResponseCode::NotFound)?;
        if let Some(VaultEntry::Credential(ref c)) = cont.entries().get(&last) {
            let cse: CredentialStoreElement = c.into();
            Ok(Some(Box::new(cse)))
        } else {
            Ok(None)
        }
    }
}
