use crate::client;
use crate::config::{self, Config};
use crate::server;
use std::collections::btree_map::IntoIter as BTreeMapIter;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Write;
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
        let subpath = match s {
            "HOME" => Some("home"),
            "XDG_RUNTIME_DIR" => Some("runtime"),
            "PATH" => return Some("/bin:/usr/bin:/sbin:/usr/sbin".into()),
            _ => None,
        }?;
        let mut root = self.root.clone();
        root.push(subpath);
        Some(root.into())
    }

    fn iter(&self) -> FakeEnvironmentIter {
        let keys = &["HOME", "PATH", "XDG_RUNTIME_DIR"];
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
    config_file: PathBuf,
}

impl TestInstance {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut server = dir.path().to_owned();
        server.push("server");
        fs::create_dir(&server).unwrap();
        let paths = &[
            "home/.local/run/lawn",
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
        let config_file = Self::write_config_file(&server);
        Self { dir, config_file }
    }

    fn write_config_file(dir: &Path) -> PathBuf {
        let mut dest = dir.to_owned();
        dest.push("config.yaml");
        let mut fp = fs::File::create(&dest).unwrap();
        write!(
            fp,
            "---
v0:
    root: true
    commands:
        printf:
            if: '!/bin/true'
            command: '!f() {{ printf \"$@\"; }};f'
        echo:
            if: true
            command: '!f() {{ printf \"$@\"; }};f'
"
        )
        .unwrap();
        dest
    }

    pub fn config(&self) -> Arc<Config> {
        let env = FakeEnvironment::new(self.dir.path());
        let iterenv = env.clone();
        let cfg = Arc::new(
            Config::new(
                move |s| env.env(s),
                move || iterenv.iter(),
                false,
                5,
                Box::new(io::Cursor::new(Vec::new())),
                Box::new(io::stderr()),
                Some(&self.config_file),
            )
            .unwrap(),
        );
        cfg.set_detach(false);
        cfg
    }

    pub fn server(&self) -> Arc<server::Server> {
        Arc::new(server::Server::new(self.config()))
    }

    pub async fn connection(&self) -> client::Connection {
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
    let ti = TestInstance::new();
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
        tokio::spawn(async move {
            s.run_async().await.unwrap();
        });
        let h = tokio::spawn(future);
        h.await.unwrap();
        s2.shutdown().await;
    })
}

#[test]
fn can_perform_test_connections() {
    let ti = Arc::new(TestInstance::new());
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
