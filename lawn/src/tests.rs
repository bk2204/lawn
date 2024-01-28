use crate::client;
use crate::config::{self, Config, ConfigBuilder};
use crate::credential::script::ScriptRunner;
use crate::credential::{CredentialHandle, CredentialStore};
use crate::server;
use async_trait::async_trait;
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_protocol::protocol::{self, Capability, ResponseCode};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::borrow::Cow;
use std::collections::btree_map::IntoIter as BTreeMapIter;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::io::{Cursor, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct FakeEnvironmentIter {
    map: BTreeMapIter<OsString, OsString>,
}

impl Iterator for FakeEnvironmentIter {
    type Item = (OsString, OsString);

    fn next(&mut self) -> Option<(OsString, OsString)> {
        let (k, v) = self.map.next()?;
        Some((k.into(), v.into()))
    }
}

#[derive(Clone)]
pub struct FakeEnvironment {
    root: PathBuf,
}

impl FakeEnvironment {
    fn new(root: &Path) -> FakeEnvironment {
        Self { root: root.into() }
    }

    fn env(&self, s: &str) -> Option<OsString> {
        let cwd = std::env::current_dir().unwrap();
        let path = std::env::var_os("PATH").unwrap();
        let subpath: Cow<'static, [u8]> = match s {
            "HOME" => Some(Cow::Borrowed(b"home" as &[u8])),
            "XDG_RUNTIME_DIR" => Some(Cow::Borrowed(b"runtime" as &[u8])),
            "LAWN_TEST_DATA_DIR" => Some(Cow::Borrowed(b"data" as &[u8])),
            "PATH" => {
                return Some(OsString::from_vec(format_bytes!(
                    b"{}/../spec/fixtures/bin:{}",
                    cwd.as_os_str().as_bytes(),
                    path.as_bytes(),
                )))
            }
            _ => None,
        }?;
        let mut root = self.root.clone();
        root.push(OsStr::from_bytes(&subpath));
        Some(root.into())
    }

    fn iter(&self) -> FakeEnvironmentIter {
        let keys = &["HOME", "PATH", "XDG_RUNTIME_DIR", "LAWN_TEST_DATA_DIR"];
        let map: BTreeMap<OsString, OsString> = keys
            .iter()
            .filter_map(|k| {
                let e = self.env(k)?;
                Some((k.into(), e))
            })
            .collect();
        FakeEnvironmentIter {
            map: map.into_iter(),
        }
    }
}

pub struct TestInstance {
    dir: tempfile::TempDir,
    config: Arc<Config>,
}

impl TestInstance {
    pub fn new(builder: Option<ConfigBuilder>, config: Option<&str>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut server = dir.path().to_owned();
        server.push("server");
        fs::create_dir(&server).unwrap();
        let paths = &[
            "home/.local/run/lawn",
            "data",
            "path",
            "run/user",
            "runtime/lawn",
            "client",
            "server",
        ];
        for p in paths {
            let mut to_create: PathBuf = dir.path().into();
            to_create.push(p);
            fs::create_dir_all(&to_create).unwrap();
        }
        let config_file = Self::write_config_file(&server, config);
        let env = FakeEnvironment::new(dir.path());
        let iterenv = env.clone();
        let mut builder = builder.unwrap_or_else(|| ConfigBuilder::new());
        builder.env(move |s| env.env(s), move || iterenv.iter());
        builder.create_runtime_dir(false);
        builder.verbosity(5);
        builder.stdout(Box::new(io::Cursor::new(Vec::new())));
        builder.stderr(Box::new(io::stdout()));
        builder.config_file(&config_file);
        builder.prng(Arc::new(Mutex::new(ChaCha20Rng::seed_from_u64(2204))));
        let cfg = Arc::new(builder.build().unwrap());
        cfg.set_detach(false);
        Self { dir, config: cfg }
    }

    fn default_config_file() -> &'static str {
        "---
v0:
    root: true
    commands:
        printf:
            if: '!/bin/true'
            command: '!f() { printf \"$@\"; };f'
        echo:
            if: true
            command: '!f() { printf \"$@\"; };f'
"
    }

    fn write_config_file(dir: &Path, config: Option<&str>) -> PathBuf {
        let mut dest = dir.to_owned();
        dest.push("config.yaml");
        let mut fp = fs::File::create(&dest).unwrap();
        let config = config.unwrap_or(Self::default_config_file());
        write!(fp, "{}", config,).unwrap();
        dest
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.clone()
    }

    pub fn server(&self) -> Arc<server::Server> {
        Arc::new(server::Server::new(self.config()))
    }

    pub async fn connection(&self) -> Arc<client::Connection> {
        let client = Arc::new(client::Client::new(self.config()));
        let mut path = self.dir.path().to_owned();
        path.push("runtime/lawn/server-0.sock");
        client.connect(path, false).await.unwrap()
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn starts_server() {
    use tokio::io::AsyncReadExt;

    let ti = TestInstance::new(None, None);
    let rt = runtime();
    rt.block_on(async {
        let s = ti.server();
        let s2 = s.clone();
        let h = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            s2.shutdown().await;
        });
        let fdrd = s.run_async().await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tokio::fs::File::from_std(fdrd).read(&mut buf).await;
        h.await
    })
    .unwrap();
}

fn with_server<F>(ti: Arc<TestInstance>, future: F)
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    use tokio::io::AsyncReadExt;

    let rt = runtime();
    rt.block_on(async {
        let s = ti.server();
        let s2 = s.clone();
        let file = s.run_async().await.unwrap();
        let mut buf = [0u8; 1];
        let _ = tokio::fs::File::from_std(file).read(&mut buf).await;
        let h = tokio::spawn(future);
        h.await.unwrap();
        s2.shutdown().await;
    })
}

#[test]
fn prng_is_reproducible_in_tests() {
    let ti = Arc::new(TestInstance::new(None, None));
    let prng = ti.config().prng();
    let mut buf = [0u8; 32];
    let mut g = prng.lock().unwrap();
    g.fill_bytes(&mut buf);
    assert_eq!(&buf, b"\x91\x44\x06\x81\x06\x91\x7a\x26\xfa\xee\x99\xba\xaf\x34\x48\x37\x20\xe6\xcc\x70\x4d\xfd\x68\x7d\xc4\xca\x04\x1f\x11\xde\x94\x7a", "expected data");
}

#[test]
fn can_perform_test_connections() {
    let ti = Arc::new(TestInstance::new(None, None));
    with_server(ti.clone(), async move {
        let c = ti.connection().await;
        c.ping().await.unwrap();
        let resp = c.negotiate_default_version().await.unwrap();
        assert_eq!(resp.version, &[0], "version is correct");
        assert_eq!(
            resp.user_agent.unwrap(),
            config::VERSION,
            "user-agent is correct"
        );
        let auth = c.auth_external().await.unwrap();
        assert_eq!(auth.method, (b"EXTERNAL" as &[u8]), "method is correct");
        assert!(auth.message.is_none(), "no message is present");
    });
}

#[test]
fn can_handle_extensions_listing_with_many_extensions() {
    use lawn_protocol::protocol;

    let mut capabilities: BTreeSet<_> = (1..=200)
        .map(|n| {
            Capability::Other(
                format!("test-capa-{}@test.ns.crustytoothpaste.net", n)
                    .into_bytes()
                    .into(),
                Some((b"v1" as &[u8]).into()),
            )
        })
        .collect();
    capabilities.extend(Capability::implemented());

    let mut cb = ConfigBuilder::new();
    cb.capabilities(capabilities.clone());
    let unwrapped: Vec<(Bytes, Option<Bytes>)> =
        capabilities.iter().map(|c| (*c).clone().into()).collect();
    let ti = Arc::new(TestInstance::new(Some(cb), None));
    with_server(ti.clone(), async move {
        // Basic setup.
        let c = ti.connection().await;
        c.ping().await.unwrap();
        let resp = c.negotiate_default_version().await.unwrap();
        assert_eq!(resp.version, &[0], "version is correct");
        assert_eq!(resp.capabilities, unwrapped);
        assert_eq!(
            resp.user_agent.unwrap(),
            config::VERSION,
            "user-agent is correct"
        );
        c.auth_external().await.unwrap();

        // Create extensions 200 extensions, each with a different number of reserved items.
        let mut set = BTreeSet::new();
        for n in 1..=200 {
            let extension = protocol::CreateExtensionRangeRequest {
                extension: (
                    format!("test-capa-{}@test.ns.crustytoothpaste.net", n)
                        .into_bytes()
                        .into(),
                    Some((b"v1" as &[u8]).into()),
                ),
                count: n,
            };
            let resp: protocol::ResponseValue<
                protocol::CreateExtensionRangeResponse,
                protocol::Empty,
            > = c
                .send_message(protocol::MessageKind::CreateExtensionRange, Some(extension))
                .await
                .unwrap()
                .unwrap();
            if let protocol::ResponseValue::Success(v) = resp {
                assert_eq!(v.range.1 - v.range.0, n, "correct number of elements");
                assert_eq!(
                    v.range.0 & 0xff000000,
                    0xff000000,
                    "bottom of range is in extension range"
                );
                assert_eq!(
                    v.range.1 & 0xff000000,
                    0xff000000,
                    "top of range is in extension range"
                );
                let ours: BTreeSet<_> = (v.range.0..v.range.1).collect();
                assert!(
                    set.is_disjoint(&ours),
                    "this range is not otherwise assigned"
                );
                set.extend(ours);
            } else {
                panic!("wrong type: continuation");
            }
        }

        // Test listing ranges.
        let resp = c
            .send_pagination_message::<_, protocol::Empty, protocol::ListExtensionRangesResponse>(
                protocol::MessageKind::ListExtensionRanges,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.len(), 200);
        for (n, val) in (1..=200).zip((&resp).into_iter()) {
            let extension = (
                format!("test-capa-{}@test.ns.crustytoothpaste.net", n)
                    .into_bytes()
                    .into(),
                Some((b"v1" as &[u8]).into()),
            );
            assert_eq!(val.extension, extension, "has correct extension");
            assert_eq!(val.range.1 - val.range.0, n, "has correct number of items");
            assert_eq!(
                val.range.0 & 0xff000000,
                0xff000000,
                "bottom of range is in extension range"
            );
            assert_eq!(
                val.range.1 & 0xff000000,
                0xff000000,
                "top of range is in extension range"
            );
        }

        // Will fail because this is a bad extension.
        let req = protocol::DeleteExtensionRangeRequest {
            extension: (
                (b"not-a-valid-extension@test.ns.crustytoothpaste.net" as &[u8]).into(),
                None,
            ),
            range: (0xff000000, 0xff000001),
        };
        let err = c
            .send_message::<_, protocol::Empty, protocol::Empty>(
                protocol::MessageKind::DeleteExtensionRange,
                Some(req),
            )
            .await
            .unwrap_err();
        let e = protocol::Error::try_from(err).unwrap();
        assert_eq!(e.code, protocol::ResponseCode::NotFound);

        // Will fail because the extension is of the wrong size.
        let req = protocol::DeleteExtensionRangeRequest {
            extension: (
                (b"test-capa-1@test.ns.crustytoothpaste.net" as &[u8]).into(),
                None,
            ),
            range: (0xff000000, 0xff0000ff),
        };
        let err = c
            .send_message::<_, protocol::Empty, protocol::Empty>(
                protocol::MessageKind::DeleteExtensionRange,
                Some(req),
            )
            .await
            .unwrap_err();
        let e = protocol::Error::try_from(err).unwrap();
        assert_eq!(e.code, protocol::ResponseCode::NotFound);

        // Delete extension assignments.
        for val in resp.iter() {
            let extension = protocol::DeleteExtensionRangeRequest {
                extension: val.extension.clone(),
                range: val.range,
            };
            assert!(c
                .send_message::<_, protocol::Empty, protocol::Empty>(
                    protocol::MessageKind::DeleteExtensionRange,
                    Some(extension)
                )
                .await
                .unwrap()
                .is_none());
        }

        // Verify that there are no extension assignments left.
        let resp = c
            .send_pagination_message::<_, protocol::Empty, protocol::ListExtensionRangesResponse>(
                protocol::MessageKind::ListExtensionRanges,
                None,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.len(), 0);
    });
}

#[test]
fn can_create_and_delete_extension_ranges_without_auth() {
    use lawn_protocol::protocol;

    let mut capabilities: BTreeSet<_> = (1..=200)
        .map(|n| {
            Capability::Other(
                format!("test-capa-{}@test.ns.crustytoothpaste.net", n)
                    .into_bytes()
                    .into(),
                Some((b"v1" as &[u8]).into()),
            )
        })
        .collect();
    capabilities.extend(Capability::implemented());

    let mut cb = ConfigBuilder::new();
    cb.capabilities(capabilities.clone());
    let unwrapped: Vec<(Bytes, Option<Bytes>)> =
        capabilities.iter().map(|c| (*c).clone().into()).collect();
    let ti = Arc::new(TestInstance::new(Some(cb), None));
    with_server(ti.clone(), async move {
        // Basic setup.
        let c = ti.connection().await;
        c.ping().await.unwrap();
        let resp = c.negotiate_default_version().await.unwrap();
        assert_eq!(resp.version, &[0], "version is correct");
        assert_eq!(resp.capabilities, unwrapped);
        assert_eq!(
            resp.user_agent.unwrap(),
            config::VERSION,
            "user-agent is correct"
        );

        // Create an extension range.
        let extension = protocol::CreateExtensionRangeRequest {
            extension: (
                (b"test-capa-1@test.ns.crustytoothpaste.net" as &[u8]).into(),
                Some((b"v1" as &[u8]).into()),
            ),
            count: 10,
        };
        let resp: protocol::ResponseValue<protocol::CreateExtensionRangeResponse, protocol::Empty> =
            c.send_message(protocol::MessageKind::CreateExtensionRange, Some(extension))
                .await
                .unwrap()
                .unwrap();
        let v = if let protocol::ResponseValue::Success(v) = resp {
            assert_eq!(v.range.1 - v.range.0, 10, "correct number of elements");
            assert_eq!(
                v.range.0 & 0xff000000,
                0xff000000,
                "bottom of range is in extension range"
            );
            assert_eq!(
                v.range.1 & 0xff000000,
                0xff000000,
                "top of range is in extension range"
            );
            v
        } else {
            panic!("wrong type: continuation");
        };

        // Delete extension assignments.
        let extension = protocol::DeleteExtensionRangeRequest {
            extension: (
                (b"test-capa-1@test.ns.crustytoothpaste.net" as &[u8]).into(),
                Some((b"v1" as &[u8]).into()),
            ),
            range: v.range,
        };
        assert!(c
            .send_message::<_, protocol::Empty, protocol::Empty>(
                protocol::MessageKind::DeleteExtensionRange,
                Some(extension)
            )
            .await
            .unwrap()
            .is_none());
    });
}

#[test]
fn can_round_trip_data_through_git_credential_helper() {
    use crate::credential::{
        Credential, CredentialClient, CredentialHandle, CredentialRequest, FieldRequest, Location,
    };
    use lawn_protocol::protocol::StoreSearchRecursionLevel;

    let config = format!(
        "{}\n{}",
        TestInstance::default_config_file(),
        "
    credential:
        if: true
        backends:
            - name: git
              type: git
              if: true
              options:
                  command: '!f() { git-backend \"$0\" \"$@\"; };f'
"
    );
    let mut capabilities = Capability::implemented();
    capabilities.insert(Capability::StoreCredential);

    let mut cb = ConfigBuilder::new();
    cb.capabilities(capabilities.clone());
    let ti = Arc::new(TestInstance::new(Some(cb), Some(&config)));
    with_server(ti.clone(), async move {
        // Basic setup.
        let c = ti.connection().await;
        c.ping().await.unwrap();
        let resp = c.negotiate_default_version().await.unwrap();
        assert_eq!(resp.version, &[0], "version is correct");
        assert_eq!(
            resp.user_agent.unwrap(),
            config::VERSION,
            "user-agent is correct"
        );
        c.auth_external().await.unwrap();

        let creds = CredentialClient::new(c).await.unwrap();
        let stores = creds.list_stores().await.unwrap();
        assert_eq!(stores.len(), 1, "one store");
        assert_eq!(stores[0].path().await, "/git/", "correct path");
        let vaults = stores[0].list_vaults().await.unwrap();
        assert_eq!(vaults.len(), 1, "one vault");
        assert_eq!(vaults[0].path().await, "/git/-/", "correct path");
        let vault = vaults.get(0).unwrap();

        let mut cred = Credential {
            username: Some(Bytes::from(b"user" as &[u8])),
            secret: Bytes::from(b"very-secret-password" as &[u8]),
            authtype: None,
            kind: "api".into(),
            title: Some("Git: https://example.com/".into()),
            description: None,
            location: vec![Location {
                protocol: Some("https".into()),
                host: Some("example.com".into()),
                port: None,
                path: None,
            }],
            service: None,
            extra: BTreeMap::new(),
            id: Bytes::from(b"" as &[u8]),
        };
        cred.id = cred.generate_id();

        vault.put_entry(&cred).await.unwrap();

        let mut req = CredentialRequest::new();
        req.protocol = FieldRequest::LiteralString("https".into());
        req.host = FieldRequest::LiteralString("example.com".into());

        let result = vault
            .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, cred, "expected credential for simple search");

        req.username = FieldRequest::LiteralBytes(Bytes::from(b"user" as &[u8]));

        let result = vault
            .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, cred, "expected credential for search with username");

        let mut newreq = req.clone();
        newreq.username = FieldRequest::LiteralBytes(Bytes::from(b"bob" as &[u8]));

        let result = vault
            .search_entry(&newreq, StoreSearchRecursionLevel::Boolean(true))
            .await
            .unwrap();
        assert_eq!(
            result, None,
            "expected credential for search with wrong username"
        );

        vault.delete_entry(&cred).await.unwrap();
        let result = vault
            .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
            .await
            .unwrap();
        assert_eq!(
            result, None,
            "expected credential for search with deleted data"
        );
    });
}

fn ce_to_pe(e: crate::credential::CredentialError) -> protocol::Error {
    protocol::Error::try_from(crate::error::Error::from(e)).unwrap()
}

#[async_trait]
trait Auther {
    async fn auth(&self, cs: &mut CredentialStore);
    async fn try_auth(&self, cs: &mut CredentialStore) -> Result<(), protocol::Error>;
}

struct PlainAuth;

#[async_trait]
impl Auther for PlainAuth {
    async fn auth(&self, cs: &mut CredentialStore) {
        self.try_auth(cs).await.unwrap()
    }

    async fn try_auth(&self, cs: &mut CredentialStore) -> Result<(), protocol::Error> {
        let resp = cs
            .authenticate(
                None,
                b"PLAIN",
                Some(Bytes::from(b"\x00\x00abc123" as &[u8])),
            )
            .await
            .map_err(|e| ce_to_pe(e))?;
        assert!(resp.0.is_none(), "no continuation ID response from PLAIN");
        assert!(resp.1.is_none(), "empty response from PLAIN");
        Ok(())
    }
}

struct KeyboardInteractiveAuth;

#[async_trait]
impl Auther for KeyboardInteractiveAuth {
    async fn auth(&self, cs: &mut CredentialStore) {
        self.try_auth(cs).await.unwrap()
    }

    async fn try_auth(&self, cs: &mut CredentialStore) -> Result<(), protocol::Error> {
        use lawn_protocol::protocol::{
            KeyboardInteractiveAuthenticationRequest, KeyboardInteractiveAuthenticationResponse,
        };

        let (id, resp) = cs
            .authenticate(None, b"keyboard-interactive", None)
            .await
            .map_err(|e| ce_to_pe(e))?;
        let id = id.expect("valid ID for keyboard-interactive first step");
        let resp = resp.unwrap();
        let req: KeyboardInteractiveAuthenticationRequest = serde_cbor::from_slice(&resp).unwrap();
        assert_eq!(req.prompts.len(), 1, "correct number of prompts");
        assert_eq!(req.prompts[0].prompt, "Password", "expected prompt text");
        assert_eq!(req.prompts[0].echo, false, "password is not echoed");
        let resp = KeyboardInteractiveAuthenticationResponse {
            responses: vec!["abc123".into()],
        };
        let resp = serde_cbor::to_vec(&resp).unwrap().into();
        let resp = cs
            .authenticate(Some(id), b"keyboard-interactive", Some(resp))
            .await
            .map_err(|e| ce_to_pe(e))?;
        assert!(
            resp.0.is_none(),
            "no ID for keyboard-interactive second step"
        );
        assert!(resp.1.is_none(), "empty response from keyboard-interactive");
        Ok(())
    }
}

#[test]
fn can_round_trip_data_through_memory_credential_helper() {
    use crate::credential::{
        Credential, CredentialClient, CredentialHandle, CredentialRequest, FieldRequest, Location,
    };
    use lawn_protocol::protocol::StoreSearchRecursionLevel;

    let authers: [Arc<dyn Auther + Send + Sync>; 2] =
        [Arc::new(PlainAuth), Arc::new(KeyboardInteractiveAuth)];

    let config = format!(
        "{}\n{}",
        TestInstance::default_config_file(),
        "
    credential:
        if: true
        backends:
            - name: memory
              type: memory
              if: true
              options:
                  token: abc123
"
    );
    let mut capabilities = Capability::implemented();
    capabilities.insert(Capability::StoreCredential);

    for auther in &authers {
        let mut cb = ConfigBuilder::new();
        cb.capabilities(capabilities.clone());

        let ti = Arc::new(TestInstance::new(Some(cb), Some(&config)));
        let auther = auther.clone();
        with_server(ti.clone(), async move {
            // Basic setup.
            let c = ti.connection().await;
            c.ping().await.unwrap();
            let resp = c.negotiate_default_version().await.unwrap();
            assert_eq!(resp.version, &[0], "version is correct");
            assert_eq!(
                resp.user_agent.unwrap(),
                config::VERSION,
                "user-agent is correct"
            );
            c.auth_external().await.unwrap();

            let creds = CredentialClient::new(c).await.unwrap();
            let mut stores = creds.list_stores().await.unwrap();
            assert_eq!(stores.len(), 1, "one store");
            assert_eq!(stores[0].path().await, "/memory/", "correct path");

            let entries = creds.list_entries().await.unwrap().collect::<Vec<_>>();
            assert_eq!(entries.len(), 1, "one store as entry");
            assert_eq!(entries[0].path, "/memory/", "correct path for entry");
            assert_eq!(
                entries[0].needs_authentication,
                Some(true),
                "needs authentication"
            );
            assert_eq!(
                entries[0].authentication_methods,
                Some(vec![
                    Bytes::from(b"PLAIN" as &[u8]),
                    Bytes::from(b"keyboard-interactive" as &[u8])
                ]),
                "needs authentication with expected methods"
            );

            let e = stores[0].list_vaults().await.unwrap_err();
            assert_eq!(ce_to_pe(e).code, ResponseCode::NeedsAuthentication);
            auther.auth(&mut stores[0]).await;

            let vaults = stores[0].list_vaults().await.unwrap();
            assert!(vaults.is_empty(), "no vaults");
            let vault = stores[0].create_vault(b"vault").await.unwrap();
            let vaults = stores[0].list_vaults().await.unwrap();
            assert_eq!(vaults.len(), 1, "no vaults");
            assert_eq!(
                vaults[0].path().await,
                b"/memory/vault/" as &[u8],
                "correct vault path"
            );
            assert_eq!(
                vaults[0].path().await,
                vault.path().await,
                "consistent vault path"
            );

            let items = vault.list_entries().await.unwrap().collect::<Vec<_>>();
            eprintln!("{:?}", items);
            assert!(items.is_empty(), "no vault entries");

            let mut cred1 = Credential {
                username: Some(Bytes::from(b"username" as &[u8])),
                secret: Bytes::from(b"secret" as &[u8]),
                authtype: Some("PLAIN".into()),
                kind: "api".into(),
                title: Some("title".into()),
                description: Some("description".into()),
                service: Some("git".into()),
                extra: BTreeMap::new(),
                id: Bytes::new(),
                location: vec![Location {
                    protocol: Some("https".into()),
                    host: Some("example.com".into()),
                    port: Some(443),
                    path: Some("/git/foo/bar".into()),
                }],
            };
            cred1.id = cred1.generate_id();
            assert_eq!(cred1.id.as_ref(), b"20aafdb3831287f75a74dd7c2843e7cbd87df92b91944f4311a940eabfa633651107f8bc24bfd563cc4c8de6f80b0e3a9e67af0e76f85044283531974a6be138", "credential has expected ID");
            let cred1_path = Bytes::from(format_bytes!(b"/memory/vault/{}", cred1.id.as_ref()));
            assert_eq!(cred1_path.as_ref(), b"/memory/vault/20aafdb3831287f75a74dd7c2843e7cbd87df92b91944f4311a940eabfa633651107f8bc24bfd563cc4c8de6f80b0e3a9e67af0e76f85044283531974a6be138", "credential path is as expected");

            let mut cred2 = Credential {
                username: Some(Bytes::from(b"someone-else" as &[u8])),
                secret: Bytes::from(b"secret" as &[u8]),
                authtype: Some("PLAIN".into()),
                kind: "api".into(),
                title: Some("title".into()),
                description: Some("description".into()),
                service: Some("git".into()),
                extra: BTreeMap::new(),
                id: Bytes::new(),
                location: vec![Location {
                    protocol: Some("https".into()),
                    host: Some("example.com".into()),
                    port: Some(443),
                    path: Some("/git/foo/baz".into()),
                }],
            };
            cred2.id = cred2.generate_id();
            let cred2_path = Bytes::from(format_bytes!(
                b"/memory/vault/foo/bar/{}",
                cred2.id.as_ref()
            ));
            assert_eq!(cred2_path.as_ref(), b"/memory/vault/foo/bar/857ff0c8c6cad14f7e4e70b3ed3a69b673a8ed297c963fce899b7d445266737a35cb67485263ceac977daed3f191a69df03a9a85ac258b33a8bcc3e76692d1ea", "credential path is as expected");

            vault.create_entry(&cred1).await.unwrap();
            let items = vault.list_entries().await.unwrap().collect::<Vec<_>>();
            assert_eq!(items.len(), 1, "one vault entry");
            assert_eq!(items[0].path, cred1_path, "vault entry has expected path");

            assert!(
                vault.get_entry(b"abc123").await.unwrap().is_none(),
                "no entry for absent credential"
            );

            let expected = vault.get_entry(&cred1.id).await.unwrap().unwrap();
            assert_eq!(expected, cred1, "cred1 is round-tripped correctly");

            let foodir = vault.create_directory(b"foo").await.unwrap();
            let bardir = foodir.create_directory(b"bar").await.unwrap();
            bardir.create_entry(&cred2).await.unwrap();
            let items = bardir.list_entries().await.unwrap().collect::<Vec<_>>();
            assert_eq!(items.len(), 1, "one vault entry in directory");
            assert_eq!(
                items[0].path, cred2_path,
                "vault entry in directory has expected path"
            );

            let items = vault.list_directories().await.unwrap();
            assert_eq!(items.len(), 1, "one directory in vault");
            assert_eq!(
                items[0].path().await.as_ref(),
                b"/memory/vault/foo/",
                "directory entry in vault has expected path"
            );

            let items = foodir.list_directories().await.unwrap();
            assert_eq!(items.len(), 1, "one directory in vault directory");
            assert_eq!(
                items[0].path().await.as_ref(),
                b"/memory/vault/foo/bar/",
                "directory entry in vault directory has expected path"
            );

            let items = bardir.list_directories().await.unwrap();
            assert_eq!(items.len(), 0, "no directory in vault directory");

            let req = CredentialRequest {
                username: FieldRequest::LiteralBytes(Bytes::copy_from_slice(b"someone-else")),
                protocol: FieldRequest::LiteralString("https".into()),
                host: FieldRequest::LiteralString("example.com".into()),
                ..Default::default()
            };
            let cred = vault
                .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cred, cred2, "recursively searched credential 2 is found");

            let req = CredentialRequest {
                username: FieldRequest::LiteralBytes(Bytes::copy_from_slice(b"username")),
                protocol: FieldRequest::LiteralString("https".into()),
                host: FieldRequest::LiteralString("example.com".into()),
                ..Default::default()
            };
            let cred = vault
                .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cred, cred1, "recursively searched credential 1 is found");

            let req = CredentialRequest {
                username: FieldRequest::LiteralBytes(Bytes::copy_from_slice(b"bob")),
                protocol: FieldRequest::LiteralString("https".into()),
                host: FieldRequest::LiteralString("example.com".into()),
                ..Default::default()
            };
            let cred = vault
                .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
                .await
                .unwrap();
            assert!(cred.is_none(), "missing credential is missing");
        });
    }
}

#[test]
fn rejects_store_auth_with_disallowed_types() {
    use crate::credential::{CredentialClient, CredentialHandle};

    let auth: [(Arc<dyn Auther + Send + Sync>, &[u8], bool); 4] = [
        (Arc::new(PlainAuth), b"PLAIN", true),
        (
            Arc::new(KeyboardInteractiveAuth),
            b"keyboard-interactive",
            true,
        ),
        (Arc::new(PlainAuth), b"keyboard-interactive", false),
        (Arc::new(KeyboardInteractiveAuth), b"PLAIN", false),
    ];

    let config = format!(
        "{}\n{}",
        TestInstance::default_config_file(),
        "
    credential:
        if: true
        backends:
            - name: memory
              type: memory
              if: true
              options:
                  token: abc123
"
    );
    let mut capabilities = Capability::implemented();
    capabilities.insert(Capability::StoreCredential);

    for (auther, scheme, success) in auth.iter() {
        let mut cb = ConfigBuilder::new();
        let capabilities = capabilities
            .iter()
            .cloned()
            .filter(|capa| {
                let (first, second) = (capa.clone()).into();
                first.as_ref() != b"auth" || second.as_deref() == Some(scheme.as_ref())
            })
            .collect::<BTreeSet<_>>();
        cb.capabilities(capabilities);

        let ti = Arc::new(TestInstance::new(Some(cb), Some(&config)));
        let auther = auther.clone();
        let success = *success;
        with_server(ti.clone(), async move {
            // Basic setup.
            let c = ti.connection().await;
            c.ping().await.unwrap();
            let resp = c.negotiate_default_version().await.unwrap();
            assert_eq!(resp.version, &[0], "version is correct");
            assert_eq!(
                resp.user_agent.unwrap(),
                config::VERSION,
                "user-agent is correct"
            );
            c.auth_external().await.unwrap();

            let creds = CredentialClient::new(c).await.unwrap();
            let mut stores = creds.list_stores().await.unwrap();
            assert_eq!(stores.len(), 1, "one store");
            assert_eq!(stores[0].path().await, "/memory/", "correct path");

            let entries = creds.list_entries().await.unwrap().collect::<Vec<_>>();
            assert_eq!(entries.len(), 1, "one store as entry");
            assert_eq!(entries[0].path, "/memory/", "correct path for entry");
            assert_eq!(
                entries[0].needs_authentication,
                Some(true),
                "needs authentication"
            );
            assert_eq!(
                entries[0].authentication_methods,
                Some(vec![
                    Bytes::from(b"PLAIN" as &[u8]),
                    Bytes::from(b"keyboard-interactive" as &[u8])
                ]),
                "needs authentication with expected methods"
            );

            let e = stores[0].list_vaults().await.unwrap_err();
            assert_eq!(ce_to_pe(e).code, ResponseCode::NeedsAuthentication);
            assert_eq!(
                auther.try_auth(&mut stores[0]).await.is_ok(),
                success,
                "success for auth type is as expected"
            );
        });
    }
}

#[test]
fn can_read_template_contexts() {
    let mut capabilities = Capability::implemented();
    capabilities.insert(Capability::ContextTemplate);

    let mut cb = ConfigBuilder::new();
    cb.capabilities(capabilities);

    let ti = Arc::new(TestInstance::new(Some(cb), None));
    with_server(ti.clone(), async move {
        // Basic setup.
        let c = ti.connection().await;
        c.ping().await.unwrap();
        let resp = c.negotiate_default_version().await.unwrap();
        assert_eq!(resp.version, &[0], "version is correct");
        assert_eq!(
            resp.user_agent.unwrap(),
            config::VERSION,
            "user-agent is correct"
        );
        c.auth_external().await.unwrap();

        let args: Arc<[Bytes]> = vec![
            Bytes::from(b"foo".as_slice()),
            Bytes::from(b"bar".as_slice()),
        ]
        .into_boxed_slice()
        .into();
        let mut cenv = BTreeMap::new();
        cenv.insert(
            Bytes::from(b"quux".as_slice()),
            Bytes::from(b"42".as_slice()),
        );
        let cenv = Arc::new(cenv);

        let cfg = ti.config();
        let g = cfg.template_context(Some(cenv.clone()), Some(args.clone()));
        let id = g.context_id();

        let (_kind, ctx) = c
            .read_template_context::<serde_cbor::Value>(id.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(ctx.senv.is_some(), "server environment exists");
        assert_eq!(
            ctx.cenv.unwrap(),
            *cenv,
            "client environment is as expected"
        );
        assert_eq!(ctx.args.unwrap(), *args, "args are as expected");

        std::mem::drop(g);

        assert!(
            c.read_template_context::<serde_cbor::Value>(id.clone())
                .await
                .unwrap()
                .is_none(),
            "template context is absent"
        );
    });
}

async fn script_runner<'a, 'b>(
    conn: Arc<client::Connection>,
    msg: &'a [u8],
    writable: &'b mut Vec<u8>,
) -> ScriptRunner<Cursor<&'a [u8]>, Cursor<&'b mut Vec<u8>>> {
    ScriptRunner::new(conn, Cursor::new(msg), Cursor::new(writable))
        .await
        .unwrap()
}

async fn run_script_command(conn: Arc<client::Connection>, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let mut runner = script_runner(conn, msg, &mut v).await;
    while runner.run_command().await.unwrap() {}
    v
}

#[test]
fn can_script_credential_ops_with_memory_backend() {
    use crate::credential::{CredentialClient, CredentialHandle};

    let authers: [Arc<dyn Auther + Send + Sync>; 2] =
        [Arc::new(PlainAuth), Arc::new(KeyboardInteractiveAuth)];

    let config = format!(
        "{}\n{}",
        TestInstance::default_config_file(),
        "
    credential:
        if: true
        backends:
            - name: memory
              type: memory
              if: true
              options:
                  token: abc123
"
    );
    let mut capabilities = Capability::implemented();
    capabilities.insert(Capability::StoreCredential);

    for auther in &authers {
        let mut cb = ConfigBuilder::new();
        cb.capabilities(capabilities.clone());

        let ti = Arc::new(TestInstance::new(Some(cb), Some(&config)));
        let auther = auther.clone();
        with_server(ti.clone(), async move {
            // Basic setup.
            let c = ti.connection().await;
            c.ping().await.unwrap();
            let resp = c.negotiate_default_version().await.unwrap();
            assert_eq!(resp.version, &[0], "version is correct");
            assert_eq!(
                resp.user_agent.unwrap(),
                config::VERSION,
                "user-agent is correct"
            );
            c.auth_external().await.unwrap();

            let creds = CredentialClient::new(c.clone()).await.unwrap();
            let mut stores = creds.list_stores().await.unwrap();
            assert_eq!(stores.len(), 1, "one store");
            assert_eq!(stores[0].path().await, "/memory/", "correct path");
            let e = stores[0].list_vaults().await.unwrap_err();
            assert_eq!(ce_to_pe(e).code, ResponseCode::NeedsAuthentication);
            auther.auth(&mut stores[0]).await;

            let vaults = stores[0].list_vaults().await.unwrap();
            assert!(vaults.is_empty(), "no vaults");

            assert_eq!(
                run_script_command(c.clone(), b"a01 mkdir /memory/vault/\n").await,
                b"a01 ok mkdir /memory/vault/\n",
                "mkdir script succeeds"
            );

            let vaults = stores[0].list_vaults().await.unwrap();
            assert_eq!(vaults.len(), 1, "no vaults");
            assert_eq!(
                vaults[0].path().await,
                b"/memory/vault/" as &[u8],
                "correct vault path"
            );
        });
    }
}
