use crate::config::Config;
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
        let paths = &["home/.local/run/lawn", "path", "run/user", "runtime/lawn", "client", "server"];
        for p in paths {
            let mut to_create: PathBuf = dir.path().into();
            to_create.push(p);
            fs::create_dir_all(&to_create).unwrap();
        }
        let config_file = Self::write_config_file(&server);
        Self {
            dir,
            config_file,
        }
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
        ).unwrap();
        dest
    }

    pub fn config(&self) -> Arc<Config> {
        let env = FakeEnvironment::new(self.dir.path());
        let iterenv = env.clone();
        let cfg = Arc::new(Config::new(
            move |s| env.env(s),
            move || iterenv.iter(),
            false,
            5,
            Box::new(io::Cursor::new(Vec::new())),
            Box::new(io::stderr()),
            Some(&self.config_file),
        ).unwrap());
        cfg.set_detach(false);
        cfg
    }

    pub fn server(&mut self) -> Arc<server::Server> {
        Arc::new(server::Server::new(self.config()))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap()
}

#[test]
fn starts_server() {
    let mut ti = TestInstance::new();
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
    }).unwrap();
}
