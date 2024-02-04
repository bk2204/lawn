use bytes::Bytes;
use lawn_protocol::protocol::{self, StoreID, StoreSearchRecursionLevel, StoreSelectorID};
use serde_cbor::Value;
use std::any::Any;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::{Arc, RwLock};

pub mod credential;

pub struct StoreManager {
    map: RwLock<HashMap<StoreID, Arc<dyn Store + Send + Sync>>>,
    id: Mutex<u32>,
}

impl StoreManager {
    pub fn new() -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            id: Mutex::new(0),
        }
    }

    pub fn next_id(&self) -> StoreID {
        let mut g = self.id.lock().unwrap();
        let val = *g;
        *g += 1;
        StoreID(val)
    }

    pub fn insert(&self, id: StoreID, ch: Arc<dyn Store + Send + Sync>) {
        let mut g = self.map.write().unwrap();
        g.insert(id, ch);
    }

    pub fn remove(&self, id: StoreID) -> Option<Arc<dyn Store + Send + Sync>> {
        let mut g = self.map.write().unwrap();
        g.remove(&id)
    }

    pub fn get(&self, id: StoreID) -> Option<Arc<dyn Store + Send + Sync>> {
        let g = self.map.read().unwrap();
        g.get(&id).cloned()
    }
}

pub struct StorePath<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> StorePath<T> {
    pub fn new(path: T) -> Option<Self> {
        let pr = path.as_ref();
        if !pr.starts_with(b"/") || pr.contains(&b'%') {
            return None;
        }
        Some(Self(path))
    }

    pub fn components(&self) -> Vec<Bytes> {
        self.0
            .as_ref()
            .split(|x| *x == b'/')
            .map(Bytes::copy_from_slice)
            .collect()
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl StorePath<Bytes> {
    pub fn from_components<U: AsRef<[u8]>>(components: &[U]) -> Option<Self> {
        if !components[0].as_ref().is_empty() {
            return None;
        }
        let size = components.iter().map(|c| c.as_ref().len()).sum::<usize>() + components.len();
        let mut v: Vec<u8> = Vec::with_capacity(size);
        for (i, c) in components.iter().enumerate() {
            let c = c.as_ref();
            if c.contains(&b'%') {
                return None;
            }
            v.extend(c);
            if i + 1 != components.len() {
                v.extend(b"/");
            }
        }
        Some(StorePath(v.into()))
    }
}

#[derive(Clone, Debug)]
pub struct StoreAuthenticationMetadata {
    methods: Vec<Bytes>,
}

impl StoreAuthenticationMetadata {
    pub fn methods(&self) -> &[Bytes] {
        &self.methods
    }
}

pub trait StoreElementEntry {
    fn store_id(&self) -> StoreID;
    fn path(&self) -> Bytes;
    fn is_directory(&self) -> bool;
    fn kind(&self) -> Bytes;
    fn needs_authentication(&self) -> Option<bool>;
    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata>;
}

impl<T: StoreElement> StoreElementEntry for T {
    fn store_id(&self) -> StoreID {
        StoreElement::store_id(self)
    }

    fn path(&self) -> Bytes {
        StoreElement::path(self)
    }

    fn is_directory(&self) -> bool {
        StoreElement::is_directory(self)
    }

    fn kind(&self) -> Bytes {
        Bytes::from(StoreElement::kind(self).to_vec())
    }

    fn needs_authentication(&self) -> Option<bool> {
        StoreElement::needs_authentication(self)
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        StoreElement::authentication_metadata(self)
    }
}

pub struct PlainStoreElementEntry {
    store_id: StoreID,
    path: Bytes,
    kind: Bytes,
    auth: Option<bool>,
    auth_meta: Option<StoreAuthenticationMetadata>,
}

impl StoreElementEntry for PlainStoreElementEntry {
    fn store_id(&self) -> StoreID {
        self.store_id
    }

    fn path(&self) -> Bytes {
        self.path.clone()
    }

    fn is_directory(&self) -> bool {
        self.path.ends_with(b"/")
    }

    fn kind(&self) -> Bytes {
        self.kind.clone()
    }

    fn needs_authentication(&self) -> Option<bool> {
        self.auth
    }

    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata> {
        self.auth_meta.clone()
    }
}

type BoxedStoreElementEntryIterator =
    Box<dyn Iterator<Item = Arc<dyn StoreElementEntry + Send + Sync>> + Send + Sync>;

pub trait StoreElement {
    fn store_id(&self) -> StoreID;
    fn id(&self) -> StoreSelectorID;
    fn path(&self) -> Bytes;

    fn is_directory(&self) -> bool {
        self.path().ends_with(b"/")
    }

    fn kind(&self) -> &[u8];
    fn contents(&self) -> Result<Option<BoxedStoreElementEntryIterator>, protocol::Error>;
    fn needs_authentication(&self) -> Option<bool>;
    fn authentication_metadata(&self) -> Option<StoreAuthenticationMetadata>;
    /// Authenticate to this store entry.
    ///
    /// `kind` is the authentication method used, and `message` is the client-side message, which
    /// may be `None` if the server is expected to speak first.
    ///
    /// Returns the server message and a boolean indicating whether more data is expected on
    /// success.
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
    fn meta(&self) -> Option<Cow<'_, BTreeMap<Bytes, Value>>>;
    fn body(&self) -> Result<Option<Box<dyn Any + Send + Sync + 'static>>, protocol::Error>;
    fn delete(&self) -> Result<(), protocol::Error>;
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
}

pub trait Store {
    fn id(&self) -> StoreID;
    fn acquire(
        &self,
        path: Bytes,
    ) -> Result<Option<Arc<dyn StoreElement + Send + Sync>>, protocol::Error>;
    fn get(&self, id: StoreSelectorID) -> Option<Arc<dyn StoreElement + Send + Sync>>;
    fn close(&self, id: StoreSelectorID) -> Result<(), protocol::Error>;
    fn delete(&self, id: StoreSelectorID) -> Result<(), protocol::Error>;
    fn create(
        &self,
        path: Bytes,
        kind: &str,
        meta: Option<&BTreeMap<Bytes, Value>>,
        body: Option<&(dyn Any + Send + Sync + 'static)>,
    ) -> Result<Arc<dyn StoreElement + Send + Sync>, protocol::Error>;
    fn search(
        &self,
        id: StoreSelectorID,
        kind: Option<Bytes>,
        pattern: Option<&(dyn Any + Send + Sync + 'static)>,
        recurse: StoreSearchRecursionLevel,
    ) -> Result<
        Box<dyn Iterator<Item = Arc<dyn StoreElement + Send + Sync>> + Send + Sync>,
        protocol::Error,
    >;
}

pub struct StoreElementEntryIterator {
    vec: VecDeque<Arc<dyn StoreElementEntry + Send + Sync>>,
}

impl StoreElementEntryIterator {
    fn new(v: VecDeque<Arc<dyn StoreElementEntry + Send + Sync>>) -> Self {
        Self { vec: v }
    }
}

impl Iterator for StoreElementEntryIterator {
    type Item = Arc<dyn StoreElementEntry + Send + Sync>;

    fn next(&mut self) -> Option<Self::Item> {
        self.vec.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::StorePath;

    #[test]
    fn storepath_parses_components() {
        let cases: &[(&[u8], Option<&[u8]>, Option<&[&[u8]]>)] = &[
            (b"/", Some(b"/"), Some(&[b"", b""])),
            (b"/git", Some(b"/git"), Some(&[b"", b"git"])),
            (b"/git/", Some(b"/git/"), Some(&[b"", b"git", b""])),
            (b"/%/", None, None),
            (b"git", None, None),
            (
                b"/git/\xfe\xff/",
                Some(b"/git/\xfe\xff/"),
                Some(&[b"", b"git", b"\xfe\xff", b""]),
            ),
        ];

        for (input, inner, components) in cases {
            let path = StorePath::new(*input);
            let computed_components = path.as_ref().map(|p| p.components());
            let computed_path = path.map(|p| p.into_inner());
            let sliced_components: Option<Vec<&[u8]>> = computed_components
                .as_ref()
                .map(|c| c.iter().map(|b| b.as_ref()).collect());

            assert_eq!(computed_path, *inner, "computed path matches");
            assert_eq!(
                sliced_components.as_deref(),
                *components,
                "computed components match"
            );

            if let Some(components) = sliced_components {
                let newpath = StorePath::from_components(&*components)
                    .unwrap()
                    .into_inner();
                assert_eq!(newpath, inner.unwrap(), "computed from components matches");
            }
        }
    }
}
