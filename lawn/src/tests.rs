use crate::client;
use crate::config::{self, Config, ConfigBuilder};
use crate::server;
use bytes::Bytes;
use format_bytes::format_bytes;
use lawn_protocol::protocol::Capability;
use std::borrow::Cow;
use std::collections::btree_map::IntoIter as BTreeMapIter;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
        let subpath: Cow<'static, [u8]> = match s {
            "HOME" => Some(Cow::Borrowed(b"home" as &[u8])),
            "XDG_RUNTIME_DIR" => Some(Cow::Borrowed(b"runtime" as &[u8])),
            "LAWN_TEST_DATA_DIR" => Some(Cow::Borrowed(b"data" as &[u8])),
            "PATH" => {
                return Some(OsString::from_vec(format_bytes!(
                    b"{}/../spec/fixtures/bin:/bin:/usr/bin:/sbin:/usr/sbin",
                    cwd.as_os_str().as_bytes()
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
    let ti = TestInstance::new(None, None);
    let rt = runtime();
    rt.block_on(async {
        let s = ti.server();
        let s2 = s.clone();
        let h = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            s2.shutdown().await;
        });
        s.run_async().await.unwrap();
        h.await
    })
    .unwrap();
}

fn with_server<F>(ti: Arc<TestInstance>, future: F)
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let rt = runtime();
    rt.block_on(async {
        let s = ti.server();
        let s2 = s.clone();
        let mut file = s.run_async().await.unwrap();
        let mut buf = [0u8; 1];
        let _ = file.read(&mut buf);
        let h = tokio::spawn(future);
        h.await.unwrap();
        s2.shutdown().await;
    })
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
