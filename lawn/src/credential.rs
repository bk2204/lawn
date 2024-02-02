use crate::client::Connection;
use crate::error::{ExtendedError, MissingElementError};
use crate::store::credential::CredentialPathComponentType;
use crate::task::block_on_async;
use async_trait::async_trait;
use blake2::Digest;
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_constants::logger::AsLogStr;
use lawn_protocol::handler;
use lawn_protocol::protocol::Error as ProtocolError;
use lawn_protocol::protocol::{
    AcquireStoreElementRequest, AcquireStoreElementResponse, AuthenticateStoreElementRequest,
    AuthenticateStoreElementResponse, CloseStoreRequest, ContinueRequest,
    CreateStoreElementRequest, CredentialStoreElement, CredentialStoreLocation,
    CredentialStoreSearchElement, DeleteStoreElementRequest, Empty, ListStoreElementsRequest,
    ListStoreElementsResponse, MessageKind, OpenStoreRequest, OpenStoreResponse,
    ReadStoreElementRequest, ReadStoreElementResponse, ResponseCode, ResponseValue,
    SearchStoreElementType, SearchStoreElementsRequest, SearchStoreElementsResponse, StoreElement,
    StoreElementWithBody, StoreID, StoreSearchRecursionLevel, StoreSelector, StoreSelectorID,
    UpdateStoreElementRequest,
};
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io;
use std::sync::Arc;
use thiserror::Error;

pub mod protocol;
pub mod script;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("empty response {0}")]
    EmptyResponse(Cow<'static, str>),
    #[error("protocol failure: {0}")]
    ProtocolFailure(#[from] crate::error::Error),
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("invalid path")]
    InvalidPath,
    #[error("not a directory")]
    NotADirectory,
    #[error("unsupported serialization")]
    UnsupportedSerialization,
}

impl ExtendedError for CredentialError {
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("credential-error")])
    }
    fn error_tag(&self) -> Cow<'static, str> {
        match self {
            Self::EmptyResponse(..) => "empty-response".into(),
            Self::ProtocolFailure(..) => "protocol-failure".into(),
            Self::NotFound => "not-found".into(),
            Self::Conflict => "conflict".into(),
            Self::InvalidPath => "invalid-path".into(),
            Self::NotADirectory => "not-a-directory".into(),
            Self::UnsupportedSerialization => "unsupported-serialization".into(),
        }
    }
}

struct ConnectionWrapper {
    conn: Arc<Connection>,
    id: StoreID,
}

impl ConnectionWrapper {
    #[allow(dead_code)]
    fn new(conn: Arc<Connection>, id: StoreID) -> Self {
        Self { conn, id }
    }

    fn store_id(&self) -> StoreID {
        self.id
    }

    fn connection(&self) -> Arc<Connection> {
        self.conn.clone()
    }
}

impl Drop for ConnectionWrapper {
    fn drop(&mut self) {
        let id = self.id;
        let conn = self.conn.clone();
        block_on_async(async move {
            let req = CloseStoreRequest { id };
            let _ = conn
                .send_message_simple::<_, Empty>(MessageKind::CloseStore, Some(req))
                .await;
        });
    }
}

pub enum CredentialObject {
    Credential(Credential),
    Store(CredentialStore),
    Vault(CredentialVault),
    Directory(CredentialDirectory),
}

pub struct CredentialClient {
    conn: Arc<ConnectionWrapper>,
    handle: CredentialDirectoryHandle,
}

impl CredentialClient {
    #[allow(dead_code)]
    pub async fn new(conn: Arc<Connection>) -> Result<Self, CredentialError> {
        let req = OpenStoreRequest {
            kind: Bytes::from(b"credential" as &[u8]),
            path: None,
            meta: None,
        };
        let resp: OpenStoreResponse = conn
            .send_message_simple(MessageKind::OpenStore, Some(req))
            .await?
            .ok_or_else(|| {
                CredentialError::EmptyResponse("when opening credential store".into())
            })?;
        let cw = Arc::new(ConnectionWrapper::new(conn, resp.id));
        let path = Bytes::from(b"/" as &[u8]);
        let id = Self::acquire_handle(cw.clone(), resp.id, path.clone()).await?;
        let handle = CredentialDirectoryHandle {
            path,
            id: Some(id),
            conn: cw.clone(),
            store_id: resp.id,
        };
        Ok(Self { conn: cw, handle })
    }

    // This is used in tests.
    #[allow(dead_code)]
    async fn list_store_elements(
        conn: Arc<ConnectionWrapper>,
        id: StoreID,
        selector: StoreSelector,
    ) -> Result<Option<Vec<StoreElement>>, CredentialError> {
        let req = ListStoreElementsRequest { id, selector };
        Ok(conn
            .connection()
            .send_pagination_message::<StoreElement, _, ListStoreElementsResponse>(
                MessageKind::ListStoreElements,
                Some(req),
            )
            .await?)
    }

    async fn acquire_handle(
        conn: Arc<ConnectionWrapper>,
        id: StoreID,
        path: Bytes,
    ) -> Result<StoreSelectorID, CredentialError> {
        let req = AcquireStoreElementRequest { id, selector: path };
        // TODO: gracefully handle NotFound
        let resp: AcquireStoreElementResponse = match conn
            .connection()
            .send_message_simple(MessageKind::AcquireStoreElement, Some(req))
            .await?
        {
            Some(resp) => resp,
            None => {
                return Err(CredentialError::EmptyResponse(
                    "when acquiring handle".into(),
                ))
            }
        };
        Ok(resp.selector)
    }

    /// List the credential stores that are available.
    // This is used in tests.
    #[allow(dead_code)]
    pub async fn list_stores(&self) -> Result<Vec<CredentialStore>, CredentialError> {
        let resp = Self::list_store_elements(
            self.conn.clone(),
            self.conn.store_id(),
            StoreSelector::Path(Bytes::from(b"/" as &[u8])),
        )
        .await?;
        match resp {
            Some(v) => Ok(v
                .iter()
                .map(|se| CredentialStore {
                    handle: CredentialDirectoryHandle {
                        path: se.path.clone(),
                        id: None,
                        conn: self.conn.clone(),
                        store_id: self.conn.store_id(),
                    },
                })
                .collect()),
            None => Err(CredentialError::EmptyResponse(
                "when listing credential stores".into(),
            )),
        }
    }

    #[allow(dead_code)]
    pub async fn get_object(
        &self,
        path: Bytes,
    ) -> Result<Option<CredentialObject>, CredentialError> {
        let store_id = self.conn.store_id();
        let handle = CredentialDirectoryHandle {
            path: path.clone(),
            id: Some(Self::acquire_handle(self.conn.clone(), store_id, path.clone()).await?),
            conn: self.conn.clone(),
            store_id,
        };
        match CredentialPathComponentType::from_path(path.clone()) {
            Some(CredentialPathComponentType::Top) | None => Ok(None),
            Some(CredentialPathComponentType::Backend) => {
                Ok(Some(CredentialObject::Store(CredentialStore { handle })))
            }
            Some(CredentialPathComponentType::Vault) => {
                Ok(Some(CredentialObject::Vault(CredentialVault { handle })))
            }
            Some(CredentialPathComponentType::VaultDirectory) => {
                Ok(Some(CredentialObject::Directory(CredentialDirectory {
                    handle,
                })))
            }
            Some(CredentialPathComponentType::Entry) => {
                match handle.get_entry_from_path(path).await {
                    Ok(Some(c)) => Ok(Some(CredentialObject::Credential(c))),
                    Ok(None) => Ok(None),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

#[async_trait]
impl CredentialHandle for CredentialClient {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError> {
        self.handle.authenticate(last_id, method, message).await
    }

    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError> {
        self.handle.list_entries().await
    }

    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError> {
        self.handle.search_entry(req, recurse).await
    }

    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError> {
        self.handle.get_entry(component).await
    }

    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.create_entry(req).await
    }

    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.update_entry(req).await
    }

    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.put_entry(req).await
    }

    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.delete_entry(req).await
    }

    async fn path(&self) -> Bytes {
        self.handle.path().await
    }
}

struct CredentialDirectoryHandle {
    path: Bytes,
    id: Option<StoreSelectorID>,
    conn: Arc<ConnectionWrapper>,
    store_id: StoreID,
}

impl fmt::Debug for CredentialDirectoryHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("CredentialDirectoryHandle")
            .field("path", &self.path.as_ref().as_log_str())
            .field("id", &self.id)
            .field("store_id", &self.store_id)
            .finish()
    }
}

impl CredentialDirectoryHandle {
    async fn get_id_mut(&mut self) -> Result<StoreSelectorID, CredentialError> {
        match self.id {
            Some(id) => Ok(id),
            None => {
                let id = CredentialClient::acquire_handle(
                    self.conn.clone(),
                    self.store_id,
                    self.path.clone(),
                )
                .await?;
                self.id = Some(id);
                Ok(id)
            }
        }
    }

    async fn get_id(&self) -> Result<StoreSelectorID, CredentialError> {
        match self.id {
            Some(id) => Ok(id),
            None => {
                let id = CredentialClient::acquire_handle(
                    self.conn.clone(),
                    self.store_id,
                    self.path.clone(),
                )
                .await?;
                Ok(id)
            }
        }
    }

    /// List the credential stores that are available.
    // This is used in tests.
    #[allow(dead_code)]
    pub async fn list_directories(&self) -> Result<Vec<CredentialDirectory>, CredentialError> {
        let resp = CredentialClient::list_store_elements(
            self.conn.clone(),
            self.store_id,
            StoreSelector::Path(self.path.clone()),
        )
        .await?;
        match resp {
            Some(v) => Ok(v
                .iter()
                .filter_map(|se| {
                    if se.kind == "directory" && se.path.ends_with(b"/") {
                        Some(CredentialDirectory {
                            handle: CredentialDirectoryHandle {
                                path: se.path.clone(),
                                id: None,
                                conn: self.conn.clone(),
                                store_id: self.store_id,
                            },
                        })
                    } else {
                        None
                    }
                })
                .collect()),
            None => Err(CredentialError::EmptyResponse(
                "when listing credential directories".into(),
            )),
        }
    }

    #[allow(dead_code)]
    pub async fn create_directory(
        &self,
        name: &[u8],
    ) -> Result<CredentialDirectoryHandle, CredentialError> {
        let path: Bytes = format_bytes!(b"{}{}/", self.path.as_ref(), name).into();
        let logger = self.conn.connection().config().logger();
        trace!(
            logger,
            "credential: creating directory {}",
            path.as_ref().as_log_str()
        );
        let req = CreateStoreElementRequest {
            id: self.store_id,
            selector: StoreSelector::Path(path.clone()),
            kind: "directory".into(),
            needs_authentication: None,
            authentication_methods: None,
            meta: None,
            body: (),
        };
        let resp: StoreElement = self
            .conn
            .connection()
            .send_message_simple(MessageKind::CreateStoreElement, Some(req))
            .await?
            .ok_or_else(|| {
                CredentialError::EmptyResponse("when creating credential store".into())
            })?;
        Ok(CredentialDirectoryHandle {
            path: resp.path,
            id: resp.id,
            conn: self.conn.clone(),
            store_id: self.store_id,
        })
    }

    async fn get_entry_from_path(
        &self,
        path: Bytes,
    ) -> Result<Option<Credential>, CredentialError> {
        let logger = self.conn.connection().config().logger();
        trace!(
            logger,
            "credential: fetching entry {}",
            path.as_ref().as_log_str()
        );
        let req = ReadStoreElementRequest {
            id: self.store_id,
            selector: StoreSelector::Path(path),
        };
        match self
            .conn
            .connection()
            .send_message_simple::<_, ReadStoreElementResponse<CredentialStoreElement>>(
                MessageKind::ReadStoreElement,
                Some(req),
            )
            .await
        {
            Ok(Some(elem)) => match elem.body.try_into() {
                Ok(cred) => Ok(Some(cred)),
                Err(_) => Err(CredentialError::UnsupportedSerialization),
            },
            Ok(None) => Err(CredentialError::UnsupportedSerialization),
            Err(e) => match ProtocolError::try_from(e) {
                Ok(pe) if pe.code == ResponseCode::NotFound => Ok(None),
                Ok(pe) => Err(crate::error::Error::from(handler::Error::from(pe)).into()),
                Err(e) => Err(e.0.into()),
            },
        }
    }
}

#[async_trait]
impl CredentialHandle for CredentialDirectoryHandle {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError> {
        let id = self.get_id_mut().await?;
        let req = AuthenticateStoreElementRequest {
            id: self.store_id,
            selector: id,
            method: Bytes::copy_from_slice(method),
            message,
        };
        let resp = if let Some(id) = last_id {
            let req = ContinueRequest {
                id,
                kind: MessageKind::AuthenticateStoreElement as u32,
                message: Some(req),
            };
            self
                .conn
                .connection()
                .send_message::<_, AuthenticateStoreElementResponse, AuthenticateStoreElementResponse>(
                    MessageKind::Continue,
                    Some(&req),
                )
                .await?
        } else {
            self
                .conn
                .connection()
                .send_message::<_, AuthenticateStoreElementResponse, AuthenticateStoreElementResponse>(
                    MessageKind::AuthenticateStoreElement,
                    Some(&req),
                )
                .await?
        };
        match (resp, last_id) {
            (Some(ResponseValue::Success(m)), _) => Ok((None, m.message)),
            (Some(ResponseValue::Continuation((_, m))), Some(lid)) => Ok((Some(lid), m.message)),
            (Some(ResponseValue::Continuation((id, m))), None) => Ok((Some(id), m.message)),
            (None, _) => return Err(CredentialError::UnsupportedSerialization),
        }
    }

    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError> {
        let id = self.get_id().await?;
        let req = ListStoreElementsRequest {
            id: self.store_id,
            selector: StoreSelector::ID(id),
        };
        let resp = self
            .conn
            .connection()
            .send_pagination_message::<StoreElement, _, ListStoreElementsResponse>(
                MessageKind::ListStoreElements,
                Some(&req),
            )
            .await?;
        let resp = resp.ok_or(CredentialError::UnsupportedSerialization)?;
        Ok(Box::new(resp.into_iter()))
    }

    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError> {
        let req: SearchStoreElementsRequest<CredentialStoreSearchElement> =
            SearchStoreElementsRequest {
                id: self.store_id,
                selector: match self.id {
                    Some(id) => StoreSelector::ID(id),
                    None => StoreSelector::Path(self.path.clone()),
                },
                recurse,
                kind: Some("credential".into()),
                body: Some(req.into()),
            };
        let resp = self.conn.connection()
            .send_pagination_message::<StoreElementWithBody<CredentialStoreElement>, _, SearchStoreElementsResponse<CredentialStoreElement>>(
                MessageKind::SearchStoreElements,
                Some(req),
            )
            .await?;
        resp.and_then(|r| {
            Some(
                (&r.first()?.body)
                    .try_into()
                    .map_err(|_| CredentialError::UnsupportedSerialization),
            )
        })
        .transpose()
    }

    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError> {
        let path = Bytes::from(format_bytes!(
            b"{}{}",
            self.path().await.as_ref(),
            component
        ));
        self.get_entry_from_path(path).await
    }

    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        let req: CreateStoreElementRequest<CredentialStoreElement> = CreateStoreElementRequest {
            id: self.store_id,
            needs_authentication: Some(false),
            authentication_methods: None,
            selector: StoreSelector::Path(self.path.clone()),
            meta: None,
            kind: "credential".into(),
            body: req.into(),
        };
        match self
            .conn
            .connection()
            .send_message_simple::<_, Empty>(MessageKind::CreateStoreElement, Some(req))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match ProtocolError::try_from(e) {
                Ok(pe) if pe.code == ResponseCode::Conflict => Err(CredentialError::Conflict),
                Ok(pe) => Err(crate::error::Error::from(handler::Error::from(pe)).into()),
                Err(e) => Err(e.0.into()),
            },
        }
    }

    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        let req: UpdateStoreElementRequest<CredentialStoreElement> = UpdateStoreElementRequest {
            id: self.store_id,
            needs_authentication: Some(false),
            authentication_methods: None,
            selector: match self.id {
                Some(id) => StoreSelector::ID(id),
                None => StoreSelector::Path(self.path.clone()),
            },
            meta: None,
            kind: "credential".into(),
            body: req.into(),
        };
        match self
            .conn
            .connection()
            .send_message_simple::<_, Empty>(MessageKind::UpdateStoreElement, Some(req))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => match ProtocolError::try_from(e) {
                Ok(pe) if pe.code == ResponseCode::NotFound => Err(CredentialError::NotFound),
                Ok(pe) => Err(crate::error::Error::from(handler::Error::from(pe)).into()),
                Err(e) => Err(e.0.into()),
            },
        }
    }

    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        match self.create_entry(req).await {
            Ok(()) => Ok(()),
            Err(CredentialError::Conflict) => self.update_entry(req).await,
            Err(e) => Err(e),
        }
    }

    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        let req = req.to_request();
        let req: SearchStoreElementsRequest<CredentialStoreSearchElement> =
            SearchStoreElementsRequest {
                id: self.store_id,
                selector: match self.id {
                    Some(id) => StoreSelector::ID(id),
                    None => StoreSelector::Path(self.path.clone()),
                },
                recurse: StoreSearchRecursionLevel::Boolean(true),
                kind: Some("credential".into()),
                body: Some(req.into()),
            };
        let resp = self.conn
            .connection()
            .send_pagination_message::<StoreElementWithBody<CredentialStoreElement>, _, SearchStoreElementsResponse<CredentialStoreElement>>(
                MessageKind::SearchStoreElements,
                Some(req),
            )
            .await?;
        let id = resp
            .and_then(|r| r.first()?.id)
            .ok_or(CredentialError::NotFound)?;
        let req = DeleteStoreElementRequest {
            id: self.store_id,
            selector: StoreSelector::ID(id),
        };
        match self
            .conn
            .connection()
            .send_message_simple::<_, Empty>(MessageKind::DeleteStoreElement, Some(req))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn path(&self) -> Bytes {
        self.path.clone()
    }
}

/// A storage method for credentials.
///
/// This corresponds to a given backend type.  For example, one might use the system keychain plus
/// a password manager, and each of those would be implemented as an struct implementing
/// `CredentialStore`.
#[derive(Debug)]
pub struct CredentialStore {
    handle: CredentialDirectoryHandle,
}

impl CredentialStore {
    /// List the credential stores that are available.
    #[allow(dead_code)]
    pub async fn list_vaults(&self) -> Result<Vec<CredentialVault>, CredentialError> {
        let resp = CredentialClient::list_store_elements(
            self.handle.conn.clone(),
            self.handle.store_id,
            StoreSelector::Path(self.handle.path.clone()),
        )
        .await?;
        match resp {
            Some(v) => Ok(v
                .iter()
                .map(|se| CredentialVault {
                    handle: CredentialDirectoryHandle {
                        path: se.path.clone(),
                        id: None,
                        conn: self.handle.conn.clone(),
                        store_id: self.handle.store_id,
                    },
                })
                .collect()),
            None => Err(CredentialError::EmptyResponse(
                "when listing credential stores".into(),
            )),
        }
    }

    #[allow(dead_code)]
    pub async fn create_vault(&self, name: &[u8]) -> Result<CredentialVault, CredentialError> {
        let handle = self.handle.create_directory(name).await?;
        Ok(CredentialVault { handle })
    }
}

#[async_trait]
impl CredentialHandle for CredentialStore {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError> {
        self.handle.authenticate(last_id, method, message).await
    }

    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError> {
        self.handle.list_entries().await
    }

    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError> {
        self.handle.search_entry(req, recurse).await
    }

    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError> {
        self.handle.get_entry(component).await
    }

    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.create_entry(req).await
    }

    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.update_entry(req).await
    }

    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.put_entry(req).await
    }

    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.delete_entry(req).await
    }

    async fn path(&self) -> Bytes {
        self.handle.path().await
    }
}

/// An arbitrary directory level for credentials.
///
/// This corresponds to a given hierarchy within a vault.  For example, one might have multiple
/// levels of directories in a vault in the system keychain manager, and each of those would be
/// implemented as an struct implementing `CredentialDirectory`.
pub struct CredentialDirectory {
    handle: CredentialDirectoryHandle,
}

impl CredentialDirectory {
    #[allow(dead_code)]
    async fn get_id(&mut self) -> Result<StoreSelectorID, CredentialError> {
        self.handle.get_id_mut().await
    }

    /// List the credential stores that are available.
    #[allow(dead_code)]
    pub async fn list_directories(&self) -> Result<Vec<CredentialDirectory>, CredentialError> {
        self.handle.list_directories().await
    }

    #[allow(dead_code)]
    pub async fn create_directory(
        &self,
        name: &[u8],
    ) -> Result<CredentialDirectory, CredentialError> {
        let handle = self.handle.create_directory(name).await?;
        Ok(CredentialDirectory { handle })
    }
}

#[async_trait]
impl CredentialHandle for CredentialDirectory {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError> {
        self.handle.authenticate(last_id, method, message).await
    }

    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError> {
        self.handle.list_entries().await
    }

    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError> {
        self.handle.search_entry(req, recurse).await
    }

    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError> {
        self.handle.get_entry(component).await
    }

    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.create_entry(req).await
    }

    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.update_entry(req).await
    }

    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.put_entry(req).await
    }

    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.delete_entry(req).await
    }

    async fn path(&self) -> Bytes {
        self.handle.path().await
    }
}

/// A storage location for credentials.
///
/// This corresponds to a given vault type.  For example, one might have multiple keychains in the
/// system keychain manager, and each of those would be implemented as an struct implementing
/// `CredentialVault`.
#[derive(Debug)]
pub struct CredentialVault {
    handle: CredentialDirectoryHandle,
}

impl CredentialVault {
    #[allow(dead_code)]
    async fn get_id(&mut self) -> Result<StoreSelectorID, CredentialError> {
        self.handle.get_id_mut().await
    }

    /// List the credential stores that are available.
    #[allow(dead_code)]
    pub async fn list_directories(&self) -> Result<Vec<CredentialDirectory>, CredentialError> {
        self.handle.list_directories().await
    }

    #[allow(dead_code)]
    pub async fn create_directory(
        &self,
        name: &[u8],
    ) -> Result<CredentialDirectory, CredentialError> {
        let handle = self.handle.create_directory(name).await?;
        Ok(CredentialDirectory { handle })
    }
}

#[async_trait]
impl CredentialHandle for CredentialVault {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError> {
        self.handle.authenticate(last_id, method, message).await
    }

    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError> {
        self.handle.list_entries().await
    }

    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError> {
        self.handle.search_entry(req, recurse).await
    }

    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError> {
        self.handle.get_entry(component).await
    }

    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.create_entry(req).await
    }

    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.update_entry(req).await
    }

    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.put_entry(req).await
    }

    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError> {
        self.handle.delete_entry(req).await
    }

    async fn path(&self) -> Bytes {
        self.handle.path().await
    }
}

#[async_trait]
pub trait CredentialHandle {
    async fn authenticate(
        &mut self,
        last_id: Option<u32>,
        method: &[u8],
        message: Option<Bytes>,
    ) -> Result<(Option<u32>, Option<Bytes>), CredentialError>;
    async fn list_entries<'a>(
        &'a self,
    ) -> Result<Box<dyn Iterator<Item = StoreElement> + 'a>, CredentialError>;
    async fn search_entry(
        &self,
        req: &CredentialRequest,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<Option<Credential>, CredentialError>;
    async fn get_entry(&self, component: &[u8]) -> Result<Option<Credential>, CredentialError>;
    async fn put_entry(&self, req: &Credential) -> Result<(), CredentialError>;
    async fn create_entry(&self, req: &Credential) -> Result<(), CredentialError>;
    async fn update_entry(&self, req: &Credential) -> Result<(), CredentialError>;
    async fn delete_entry(&self, req: &Credential) -> Result<(), CredentialError>;
    async fn path(&self) -> Bytes;
}

pub trait CredentialSet {}

// This value is serialized in some of the backends.  If you change it incompatibly, be sure to
// separate that usage out into a separate struct.
#[derive(Serialize, Deserialize, Default, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Location {
    pub(crate) protocol: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) port: Option<u16>,
    pub(crate) path: Option<String>,
}

impl Location {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn has_contents(&self) -> bool {
        self.protocol.is_some() || self.host.is_some() || self.path.is_some()
    }

    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn as_url(&self) -> Option<String> {
        // TODO: handle IPv6 addresses as hostnames.
        let mut s = format!(
            "{}://{}",
            self.protocol.as_deref()?,
            self.host.as_deref().unwrap_or_default()
        );
        if let Some(port) = self.port {
            s += &format!(":{}", port);
        }
        match &self.path {
            Some(path) if path.starts_with('/') => s += path,
            Some(path) => s += &format!("/{}", path),
            None => s += "/",
        };
        Some(s)
    }
}

impl From<url::Url> for Location {
    fn from(url: url::Url) -> Location {
        Location::from(&url)
    }
}

impl<'a> From<&'a url::Url> for Location {
    fn from(url: &'a url::Url) -> Location {
        Location {
            protocol: Some(url.scheme().into()),
            host: url.host_str().map(|host| host.into()),
            path: Some(url.path().into()),
            port: url.port(),
        }
    }
}

impl From<CredentialStoreLocation> for Location {
    fn from(cse: CredentialStoreLocation) -> Location {
        Location {
            protocol: cse.protocol,
            host: cse.host,
            port: cse.port,
            path: cse.path,
        }
    }
}

impl<'a> From<&'a CredentialStoreLocation> for Location {
    fn from(cse: &'a CredentialStoreLocation) -> Location {
        Location {
            protocol: cse.protocol.clone(),
            host: cse.host.clone(),
            port: cse.port,
            path: cse.path.clone(),
        }
    }
}

impl<'a> From<&'a mut CredentialStoreLocation> for Location {
    fn from(cse: &'a mut CredentialStoreLocation) -> Location {
        Location::from(cse as &CredentialStoreLocation)
    }
}

impl From<Location> for CredentialStoreLocation {
    fn from(cse: Location) -> CredentialStoreLocation {
        CredentialStoreLocation {
            protocol: cse.protocol,
            host: cse.host,
            port: cse.port,
            path: cse.path,
        }
    }
}

impl<'a> From<&'a Location> for CredentialStoreLocation {
    fn from(cse: &'a Location) -> CredentialStoreLocation {
        CredentialStoreLocation {
            protocol: cse.protocol.clone(),
            host: cse.host.clone(),
            port: cse.port,
            path: cse.path.clone(),
        }
    }
}

impl<'a> From<&'a mut Location> for CredentialStoreLocation {
    fn from(cse: &'a mut Location) -> CredentialStoreLocation {
        CredentialStoreLocation::from(cse as &Location)
    }
}

// This value is serialized in some of the backends.  If you change it incompatibly, be sure to
// separate that usage out into a separate struct.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Credential {
    pub(crate) username: Option<Bytes>,
    pub(crate) secret: Bytes,
    pub(crate) authtype: Option<String>,
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) title: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) location: Vec<Location>,
    pub(crate) service: Option<String>,
    pub(crate) extra: BTreeMap<String, Value>,
    #[serde(skip)]
    pub(crate) id: Bytes,
}

impl Default for Credential {
    fn default() -> Self {
        Self::new()
    }
}

impl Credential {
    pub fn new() -> Self {
        Self {
            username: None,
            secret: Bytes::new(),
            authtype: None,
            title: None,
            kind: String::new(),
            description: None,
            location: Vec::new(),
            service: None,
            extra: BTreeMap::new(),
            id: Bytes::new(),
        }
    }

    pub fn username(&self) -> Option<Bytes> {
        self.username.clone()
    }

    pub fn secret(&self) -> Bytes {
        self.secret.clone()
    }

    pub fn generate_id(&self) -> Bytes {
        let mut digest = blake2::Blake2b512::new();
        digest.update("lawn:credential:id:v1:");
        digest.update(serde_cbor::to_vec(self).unwrap());
        hex::encode(digest.finalize()).into()
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn id(&self) -> Bytes {
        self.id.clone()
    }

    pub fn authtype(&self) -> Option<&str> {
        self.authtype.as_deref()
    }

    pub fn location(&self) -> &[Location] {
        &self.location
    }

    pub fn service(&self) -> Option<&str> {
        self.service.as_deref()
    }

    pub fn extra(&self) -> &BTreeMap<String, Value> {
        &self.extra
    }

    fn byte_request(req: Option<Bytes>) -> FieldRequest {
        match req {
            Some(r) => FieldRequest::LiteralBytes(r),
            None => FieldRequest::Any,
        }
    }

    fn str_request(req: Option<&str>) -> FieldRequest {
        match req {
            Some(r) => FieldRequest::LiteralString(r.into()),
            None => FieldRequest::Any,
        }
    }

    pub fn to_request(&self) -> CredentialRequest {
        CredentialRequest {
            username: Self::byte_request(self.username.clone()),
            authtype: Self::str_request(self.authtype.as_deref()),
            kind: Self::str_request(Some(&self.kind)),
            protocol: Self::str_request(
                self.location
                    .first()
                    .and_then(|loc| loc.protocol.as_deref()),
            ),
            host: Self::str_request(self.location.first().and_then(|loc| loc.host.as_deref())),
            path: Self::str_request(self.location.first().and_then(|loc| loc.path.as_deref())),
            id: Self::byte_request(Some(self.id.clone())),
            title: Self::str_request(self.title.as_deref()),
            description: Self::str_request(self.description.as_deref()),
            service: Self::str_request(self.service.as_deref()),
            extra: BTreeMap::new(),
        }
    }
}

impl TryFrom<CredentialStoreElement> for Credential {
    type Error = MissingElementError<CredentialStoreElement>;
    fn try_from(cse: CredentialStoreElement) -> Result<Credential, Self::Error> {
        let secret = match cse.secret {
            Some(secret) => secret,
            None => return Err(MissingElementError::new("secret", cse)),
        };
        Ok(Credential {
            username: cse.username,
            secret,
            authtype: cse.authtype,
            kind: cse.kind,
            title: cse.title,
            description: cse.description,
            location: cse.location.iter().map(|loc| loc.into()).collect(),
            service: cse.service,
            extra: cse.extra,
            id: cse.id,
        })
    }
}

impl<'a> TryFrom<&'a CredentialStoreElement> for Credential {
    type Error = MissingElementError<&'a CredentialStoreElement>;
    fn try_from(cse: &'a CredentialStoreElement) -> Result<Credential, Self::Error> {
        let secret = match cse.secret {
            Some(ref secret) => secret.clone(),
            None => return Err(MissingElementError::new("secret", cse)),
        };
        Ok(Credential {
            username: cse.username.clone(),
            secret,
            authtype: cse.authtype.clone(),
            kind: cse.kind.clone(),
            title: cse.title.clone(),
            description: cse.description.clone(),
            location: cse.location.iter().map(|loc| loc.into()).collect(),
            service: cse.service.clone(),
            extra: cse.extra.clone(),
            id: cse.id.clone(),
        })
    }
}

impl<'a> TryFrom<&'a mut CredentialStoreElement> for Credential {
    type Error = MissingElementError<&'a mut CredentialStoreElement>;
    fn try_from(cse: &'a mut CredentialStoreElement) -> Result<Credential, Self::Error> {
        match Credential::try_from(cse as &CredentialStoreElement) {
            Ok(r) => Ok(r),
            Err(_) => Err(MissingElementError::new("secret", cse)),
        }
    }
}

impl From<Credential> for CredentialStoreElement {
    fn from(cse: Credential) -> CredentialStoreElement {
        CredentialStoreElement {
            username: cse.username,
            secret: Some(cse.secret),
            authtype: cse.authtype,
            kind: cse.kind,
            title: cse.title,
            description: cse.description,
            location: cse.location.iter().map(|loc| loc.into()).collect(),
            service: cse.service,
            extra: cse.extra,
            id: cse.id,
        }
    }
}

impl<'a> From<&'a Credential> for CredentialStoreElement {
    fn from(cse: &'a Credential) -> CredentialStoreElement {
        CredentialStoreElement {
            username: cse.username.clone(),
            secret: Some(cse.secret.clone()),
            authtype: cse.authtype.clone(),
            kind: cse.kind.clone(),
            title: cse.title.clone(),
            description: cse.description.clone(),
            location: cse.location.iter().map(|loc| loc.into()).collect(),
            service: cse.service.clone(),
            extra: cse.extra.clone(),
            id: cse.id.clone(),
        }
    }
}

impl<'a> From<&'a mut Credential> for CredentialStoreElement {
    fn from(cse: &'a mut Credential) -> CredentialStoreElement {
        CredentialStoreElement::from(cse as &Credential)
    }
}

#[derive(Debug, Error)]
pub enum CredentialParserError {
    #[error("invalid serialization: {0}")]
    InvalidSerialization(Cow<'static, str>),
    #[error("unsatisfiable request {1} for field {0}")]
    UnsatisfiableRequest(Cow<'static, str>, Cow<'static, str>),
    #[error("i/o error: {0}")]
    IOError(#[from] io::Error),
    #[error("no such handle")]
    NoSuchHandle,
    #[error("spawn error")]
    SpawnError,
    #[error("unauthenticated")]
    Unauthenticated,
    #[error("protocol message too large")]
    DataTooLarge,
    #[error("unlistable")]
    Unlistable,
}

#[cfg(test)]
impl Clone for CredentialParserError {
    fn clone(&self) -> Self {
        match self {
            CredentialParserError::IOError(e) => match e.raw_os_error() {
                Some(e) => CredentialParserError::IOError(io::Error::from_raw_os_error(e)),
                None => CredentialParserError::IOError(io::Error::new(e.kind(), format!("{}", e))),
            },
            x => x.clone(),
        }
    }
}

#[derive(Default, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum FieldRequest {
    LiteralBytes(Bytes),
    LiteralString(String),
    Set(BTreeSet<FieldRequest>),
    Sequence(Vec<FieldRequest>),
    #[default]
    Any,
    None,
}

impl FieldRequest {
    fn matches_bytes(&self, v: Option<&Bytes>) -> bool {
        match (self, v) {
            (FieldRequest::LiteralBytes(b), Some(v)) => b == v,
            (FieldRequest::LiteralBytes(_), _) => false,
            (FieldRequest::LiteralString(s), Some(v)) => s.as_bytes() == v,
            (FieldRequest::LiteralString(_), _) => false,
            (FieldRequest::Set(s), v) => s.iter().any(|req| req.matches_bytes(v)),
            (FieldRequest::Sequence(s), v) => s.iter().any(|req| req.matches_bytes(v)),
            (FieldRequest::Any, _) => true,
            (FieldRequest::None, v) => v.is_none(),
        }
    }

    fn matches_string(&self, v: Option<&str>) -> bool {
        match (self, v) {
            (FieldRequest::LiteralString(s), Some(v)) => s == v,
            (FieldRequest::LiteralString(_), _) => false,
            (FieldRequest::LiteralBytes(b), Some(v)) => b == v.as_bytes(),
            (FieldRequest::LiteralBytes(_), _) => false,
            (FieldRequest::Set(s), v) => s.iter().any(|req| req.matches_string(v)),
            (FieldRequest::Sequence(s), v) => s.iter().any(|req| req.matches_string(v)),
            (FieldRequest::Any, _) => true,
            (FieldRequest::None, v) => v.is_none(),
        }
    }

    fn matches_value(&self, v: &Value) -> bool {
        match (self, v) {
            (FieldRequest::LiteralString(s), Value::Text(v)) => s == v,
            (FieldRequest::LiteralString(s), Value::Bytes(v)) => s.as_bytes() == *v,
            (FieldRequest::LiteralString(_), _) => false,
            (FieldRequest::LiteralBytes(b), Value::Bytes(v)) => b == v,
            (FieldRequest::LiteralBytes(b), Value::Text(v)) => b == v.as_bytes(),
            (FieldRequest::LiteralBytes(_), _) => false,
            (FieldRequest::Set(s), v) => s.iter().any(|req| req.matches_value(v)),
            (FieldRequest::Sequence(s), v) => s.iter().any(|req| req.matches_value(v)),
            (FieldRequest::Any, _) => true,
            (FieldRequest::None, Value::Null) => true,
            (FieldRequest::None, _) => false,
        }
    }
}

#[derive(Default)]
pub struct UnsupportedSerialization<T>(T);

impl TryFrom<SearchStoreElementType> for FieldRequest {
    type Error = UnsupportedSerialization<SearchStoreElementType>;

    fn try_from(sset: SearchStoreElementType) -> Result<FieldRequest, Self::Error> {
        match sset {
            SearchStoreElementType::Literal(Value::Text(s)) => Ok(FieldRequest::LiteralString(s)),
            SearchStoreElementType::Literal(Value::Bytes(b)) => {
                Ok(FieldRequest::LiteralBytes(b.into()))
            }
            SearchStoreElementType::Literal(_) => Err(UnsupportedSerialization(sset)),
            SearchStoreElementType::Set(ref s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Set(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Sequence(ref s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Sequence(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Any(_) => Ok(FieldRequest::Any),
            SearchStoreElementType::None(_) => Ok(FieldRequest::None),
        }
    }
}

impl<'a> TryFrom<&'a SearchStoreElementType> for FieldRequest {
    type Error = UnsupportedSerialization<&'a SearchStoreElementType>;

    fn try_from(sset: &'a SearchStoreElementType) -> Result<FieldRequest, Self::Error> {
        match sset {
            SearchStoreElementType::Literal(Value::Text(s)) => {
                Ok(FieldRequest::LiteralString(s.clone()))
            }
            SearchStoreElementType::Literal(Value::Bytes(b)) => {
                Ok(FieldRequest::LiteralBytes(b.clone().into()))
            }
            SearchStoreElementType::Literal(_) => Err(UnsupportedSerialization(sset)),
            SearchStoreElementType::Set(s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Set(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Sequence(s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Sequence(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Any(_) => Ok(FieldRequest::Any),
            SearchStoreElementType::None(_) => Ok(FieldRequest::None),
        }
    }
}

impl<'a> TryFrom<&'a mut SearchStoreElementType> for FieldRequest {
    type Error = UnsupportedSerialization<&'a mut SearchStoreElementType>;

    fn try_from(sset: &'a mut SearchStoreElementType) -> Result<FieldRequest, Self::Error> {
        match sset {
            SearchStoreElementType::Literal(Value::Text(s)) => {
                Ok(FieldRequest::LiteralString(s.clone()))
            }
            SearchStoreElementType::Literal(Value::Bytes(b)) => {
                Ok(FieldRequest::LiteralBytes(b.clone().into()))
            }
            SearchStoreElementType::Literal(_) => Err(UnsupportedSerialization(sset)),
            SearchStoreElementType::Set(s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Set(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Sequence(s) => match s
                .iter()
                .map(FieldRequest::try_from)
                .collect::<Result<_, _>>()
            {
                Ok(s) => Ok(FieldRequest::Sequence(s)),
                Err(_) => Err(UnsupportedSerialization(sset)),
            },
            SearchStoreElementType::Any(_) => Ok(FieldRequest::Any),
            SearchStoreElementType::None(_) => Ok(FieldRequest::None),
        }
    }
}

impl From<FieldRequest> for SearchStoreElementType {
    fn from(fr: FieldRequest) -> Self {
        match fr {
            FieldRequest::LiteralBytes(b) => {
                SearchStoreElementType::Literal(Value::Bytes(b.into()))
            }
            FieldRequest::LiteralString(s) => SearchStoreElementType::Literal(Value::Text(s)),
            FieldRequest::Set(s) => {
                SearchStoreElementType::Set(s.iter().map(SearchStoreElementType::from).collect())
            }
            FieldRequest::Sequence(s) => SearchStoreElementType::Sequence(
                s.iter().map(SearchStoreElementType::from).collect(),
            ),
            FieldRequest::Any => SearchStoreElementType::Any(()),
            FieldRequest::None => SearchStoreElementType::None(()),
        }
    }
}

impl<'a> From<&'a FieldRequest> for SearchStoreElementType {
    fn from(fr: &'a FieldRequest) -> Self {
        match fr {
            FieldRequest::LiteralBytes(b) => {
                SearchStoreElementType::Literal(Value::Bytes(b.clone().into()))
            }
            FieldRequest::LiteralString(s) => {
                SearchStoreElementType::Literal(Value::Text(s.clone()))
            }
            FieldRequest::Set(s) => {
                SearchStoreElementType::Set(s.iter().map(SearchStoreElementType::from).collect())
            }
            FieldRequest::Sequence(s) => SearchStoreElementType::Sequence(
                s.iter().map(SearchStoreElementType::from).collect(),
            ),
            FieldRequest::Any => SearchStoreElementType::Any(()),
            FieldRequest::None => SearchStoreElementType::None(()),
        }
    }
}

impl<'a> From<&'a mut FieldRequest> for SearchStoreElementType {
    fn from(fr: &'a mut FieldRequest) -> Self {
        match fr {
            FieldRequest::LiteralBytes(b) => {
                SearchStoreElementType::Literal(Value::Bytes(b.clone().into()))
            }
            FieldRequest::LiteralString(s) => {
                SearchStoreElementType::Literal(Value::Text(s.clone()))
            }
            FieldRequest::Set(s) => {
                SearchStoreElementType::Set(s.iter().map(SearchStoreElementType::from).collect())
            }
            FieldRequest::Sequence(s) => SearchStoreElementType::Sequence(
                s.iter().map(SearchStoreElementType::from).collect(),
            ),
            FieldRequest::Any => SearchStoreElementType::Any(()),
            FieldRequest::None => SearchStoreElementType::None(()),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct CredentialRequest {
    pub(crate) username: FieldRequest,
    pub(crate) authtype: FieldRequest,
    pub(crate) protocol: FieldRequest,
    pub(crate) kind: FieldRequest,
    pub(crate) host: FieldRequest,
    pub(crate) title: FieldRequest,
    pub(crate) description: FieldRequest,
    pub(crate) path: FieldRequest,
    pub(crate) service: FieldRequest,
    pub(crate) id: FieldRequest,
    pub(crate) extra: BTreeMap<String, FieldRequest>,
}

impl CredentialRequest {
    pub fn new() -> Self {
        Self {
            username: FieldRequest::Any,
            authtype: FieldRequest::Any,
            protocol: FieldRequest::Any,
            title: FieldRequest::Any,
            kind: FieldRequest::Any,
            description: FieldRequest::Any,
            host: FieldRequest::Any,
            path: FieldRequest::Any,
            service: FieldRequest::Any,
            id: FieldRequest::Any,
            extra: BTreeMap::new(),
        }
    }

    pub fn matches(&self, cred: &Credential) -> bool {
        self.username.matches_bytes(cred.username.as_ref()) &&
        self.authtype.matches_string(cred.authtype.as_deref()) &&
        self.kind.matches_string(Some(&cred.kind)) &&
        // TODO: match Any and None with no location
        cred.location.iter().any(|loc|
        self.protocol.matches_string(loc.protocol.as_deref()) &&
        self.host.matches_string(loc.host.as_deref()) &&
        self.path.matches_string(loc.path.as_deref())) &&
        self.service.matches_string(cred.service.as_deref()) &&
        self.title.matches_string(cred.title.as_deref()) &&
        self.description.matches_string(cred.description.as_deref()) &&
        self.id.matches_bytes(Some(&cred.id)) &&
        self.extra.iter().all(|(k, v)| {
            let val = cred.extra.get(k).unwrap_or(&Value::Null);
            v.matches_value(val)
        })
    }
}

impl<'a> From<&'a mut CredentialRequest> for CredentialStoreSearchElement {
    fn from(cr: &'a mut CredentialRequest) -> Self {
        Self::from(cr as &'a CredentialRequest)
    }
}

impl<'a> From<&'a CredentialRequest> for CredentialStoreSearchElement {
    fn from(cr: &'a CredentialRequest) -> Self {
        CredentialStoreSearchElement {
            username: (&cr.username).into(),
            secret: SearchStoreElementType::Any(()),
            authtype: (&cr.authtype).into(),
            kind: (&cr.kind).into(),
            protocol: (&cr.protocol).into(),
            host: (&cr.host).into(),
            path: (&cr.path).into(),
            title: (&cr.title).into(),
            description: (&cr.description).into(),
            service: (&cr.service).into(),
            id: (&cr.id).into(),
            extra: cr
                .extra
                .iter()
                .map(|(k, v)| (k.clone(), (*v).clone().into()))
                .collect(),
        }
    }
}

impl From<CredentialRequest> for CredentialStoreSearchElement {
    fn from(cr: CredentialRequest) -> Self {
        Self::from(&cr)
    }
}

impl TryFrom<CredentialStoreSearchElement> for CredentialRequest {
    type Error = UnsupportedSerialization<CredentialStoreSearchElement>;

    fn try_from(csse: CredentialStoreSearchElement) -> Result<Self, Self::Error> {
        let f = |csse: &CredentialStoreSearchElement| {
            Some(CredentialRequest {
                username: (&csse.username).try_into().ok()?,
                authtype: (&csse.authtype).try_into().ok()?,
                kind: (&csse.kind).try_into().ok()?,
                protocol: (&csse.protocol).try_into().ok()?,
                host: (&csse.host).try_into().ok()?,
                path: (&csse.path).try_into().ok()?,
                title: (&csse.title).try_into().ok()?,
                description: (&csse.description).try_into().ok()?,
                service: (&csse.service).try_into().ok()?,
                id: (&csse.id).try_into().ok()?,
                extra: csse
                    .extra
                    .iter()
                    .map(|(k, v)| {
                        Ok::<_, UnsupportedSerialization<_>>((k.clone(), (*v).clone().try_into()?))
                    })
                    .collect::<Result<_, _>>()
                    .ok()?,
            })
        };
        match f(&csse) {
            Some(cr) => Ok(cr),
            None => Err(UnsupportedSerialization(csse)),
        }
    }
}

impl<'a> TryFrom<&'a CredentialStoreSearchElement> for CredentialRequest {
    type Error = UnsupportedSerialization<&'a CredentialStoreSearchElement>;

    fn try_from(csse: &'a CredentialStoreSearchElement) -> Result<Self, Self::Error> {
        let f = |csse: &CredentialStoreSearchElement| {
            Some(CredentialRequest {
                username: (&csse.username).try_into().ok()?,
                authtype: (&csse.authtype).try_into().ok()?,
                kind: (&csse.kind).try_into().ok()?,
                protocol: (&csse.protocol).try_into().ok()?,
                host: (&csse.host).try_into().ok()?,
                title: (&csse.title).try_into().ok()?,
                description: (&csse.description).try_into().ok()?,
                path: (&csse.path).try_into().ok()?,
                service: (&csse.service).try_into().ok()?,
                id: (&csse.id).try_into().ok()?,
                extra: csse
                    .extra
                    .iter()
                    .map(|(k, v)| {
                        Ok::<_, UnsupportedSerialization<_>>((k.clone(), (*v).clone().try_into()?))
                    })
                    .collect::<Result<_, _>>()
                    .ok()?,
            })
        };
        match f(&csse) {
            Some(cr) => Ok(cr),
            None => Err(UnsupportedSerialization(csse)),
        }
    }
}

impl<'a> TryFrom<&'a mut CredentialStoreSearchElement> for CredentialRequest {
    type Error = UnsupportedSerialization<&'a mut CredentialStoreSearchElement>;

    fn try_from(csse: &'a mut CredentialStoreSearchElement) -> Result<Self, Self::Error> {
        match CredentialRequest::try_from(csse as &CredentialStoreSearchElement) {
            Ok(cr) => Ok(cr),
            Err(_) => Err(UnsupportedSerialization(csse)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Location;

    #[test]
    fn formats_locations_as_url() {
        let cases = &[
            (
                Some("https"),
                Some("example.com"),
                None,
                Some("/foo"),
                Some("https://example.com/foo"),
            ),
            (
                Some("https"),
                Some("example.com"),
                None,
                Some("foo"),
                Some("https://example.com/foo"),
            ),
            (
                Some("https"),
                Some("example.com"),
                Some(3128),
                Some("/foo"),
                Some("https://example.com:3128/foo"),
            ),
            (
                Some("https"),
                Some("example.com"),
                None,
                None,
                Some("https://example.com/"),
            ),
            (
                Some("cert"),
                None,
                None,
                Some("/dev/null"),
                Some("cert:///dev/null"),
            ),
            (
                Some("file"),
                None,
                None,
                Some("/dev/null"),
                Some("file:///dev/null"),
            ),
        ];

        for (proto, hostname, port, path, result) in cases {
            let loc = Location {
                protocol: proto.map(ToOwned::to_owned),
                host: hostname.map(ToOwned::to_owned),
                port: *port,
                path: path.map(ToOwned::to_owned),
            };
            assert_eq!(loc.as_url().as_deref(), *result);
        }
    }
}
