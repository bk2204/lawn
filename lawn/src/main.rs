extern crate bytes;
extern crate clap;
extern crate daemonize;
extern crate hex;
#[macro_use]
extern crate lawn_constants;
extern crate lawn_protocol;
extern crate libc;
extern crate num_derive;
extern crate tokio;

use crate::client::Connection;
use crate::credential::protocol::git::GitProtocolHandler;
use crate::encoding::{escape, osstr, path};
use bytes::Bytes;
use clap::{App, Arg, ArgMatches};
use lawn_protocol::config::Logger;
use lawn_protocol::protocol::{
    ClipboardChannelOperation, ClipboardChannelTarget, StoreSearchRecursionLevel,
};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;

mod channel;
mod client;
mod config;
mod credential;
mod encoding;
mod error;
mod fs_proxy;
mod serializer;
mod server;
mod ssh_proxy;
mod store;
mod task;
mod template;
#[cfg(not(miri))]
#[cfg(test)]
mod tests;
mod unix;

use error::{Error, ErrorKind};

#[allow(clippy::redundant_closure)]
fn config(verbosity: i32) -> Result<Arc<config::Config>, Error> {
    let config: Option<PathBuf> = std::env::var_os("XDG_CONFIG_HOME")
        .map(|x| x.into())
        .or_else(|| {
            std::env::var_os("HOME").map(|x| {
                let mut path: PathBuf = x.into();
                path.push(".config");
                path
            })
        });
    let config = config.map(|x| {
        let mut path = x;
        path.push("lawn");
        path.push("config.yaml");
        path
    });
    Ok(Arc::new(config::Config::new(
        |var| std::env::var_os(var),
        std::env::vars_os,
        true,
        verbosity,
        Box::new(std::io::stdout()),
        Box::new(std::io::stderr()),
        config.as_ref(),
    )?))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn prune_socket(p: &Path, logger: Arc<config::Logger>) {
    trace!(logger, "autopruning socket {}", escape(path(p)));
    let _ = std::fs::remove_file(p);
}

fn find_server_socket(
    handle: &Handle,
    socket: Option<&OsStr>,
    config: Arc<config::Config>,
) -> Option<UnixStream> {
    let logger = config.logger();
    if let Some(socket) = socket {
        debug!(logger, "trying specified socket {}", escape(osstr(socket)));
        return match UnixStream::connect(socket) {
            Ok(sock) => Some(sock),
            Err(_) => None,
        };
    }
    if let Some(path) = std::env::var_os("SSH_AUTH_SOCK") {
        debug!(logger, "trying SSH socket {}", escape(osstr(&*path)));
        match UnixStream::connect(path) {
            Ok(sock) => {
                let log = logger.clone();
                let cfg = config.clone();
                let res = handle.block_on(async move {
                    debug!(log, "SSH socket: performing client probe");
                    ssh_proxy::Proxy::client_probe(cfg.clone(), sock).await
                });
                let res = match res {
                    Ok(sock) => {
                        let config = config.clone();
                        let _eg = handle.enter();
                        let (sa, sb) = tokio::net::UnixStream::pair().unwrap();
                        tokio::spawn(async {
                            let p = ssh_proxy::Proxy::new(
                                config,
                                None,
                                sa,
                                tokio::net::UnixStream::from_std(sock).unwrap(),
                            );
                            let _ = p.run_client().await;
                        });
                        Ok(sb)
                    }
                    Err(e) => {
                        debug!(logger, "failed to connect to SSH socket");
                        Err(e)
                    }
                };
                if let Ok(sock) = res {
                    return Some(sock.into_std().unwrap());
                }
            }
            Err(e) => {
                debug!(logger, "SSH socket: failed to connect: {}", e);
            }
        }
    }
    let mut wanted = None;
    for p in config.sockets() {
        match p.file_name() {
            Some(file) => {
                if !file.as_bytes().starts_with(b"server") {
                    continue;
                }
            }
            None => continue,
        }
        trace!(logger, "trying socket {}", escape(path(&*p)));
        match UnixStream::connect(&p) {
            Ok(sock) => {
                debug!(
                    logger,
                    "successfully connected to socket {}",
                    escape(path(&*p))
                );
                if wanted.is_none() {
                    if config.autoprune_sockets() {
                        wanted = Some(sock);
                    } else {
                        return Some(sock);
                    }
                }
            }
            Err(e) => match wanted {
                Some(_) => {
                    if config.autoprune_sockets() {
                        prune_socket(&p, logger.clone());
                    }
                }
                None => {
                    debug!(
                        logger,
                        "failed to connect to socket {}: {}",
                        escape(path(&*p)),
                        e
                    );
                    if config.autoprune_sockets() {
                        prune_socket(&p, logger.clone());
                    }
                }
            },
        }
    }
    wanted
}

fn autospawn_server(config: Arc<config::Config>) -> Result<(), Error> {
    let logger = config.logger();
    match config.is_root() {
        Ok(true) => {
            debug!(logger, "autospawning server");
            let server = server::Server::new(config);
            if let Err(e) = server.run_forked() {
                error!(logger, "failed to autospawn server: {}", e);
                Err(e)
            } else {
                Ok(())
            }
        }
        Ok(false) => {
            debug!(logger, "not root, not autospawning server");
            Err(Error::new(ErrorKind::NotRootMachine))
        }
        Err(e) => {
            debug!(
                logger,
                "unable to determine whether we are the root instance: {}", e
            );
            Err(e)
        }
    }
}

fn find_vacant_socket(config: Arc<config::Config>, kind: &str) -> Result<PathBuf, Error> {
    let p = config.runtime_dir();
    for i in 0..1_000_000 {
        let mut p = p.clone();
        p.push(format!("{}-{}.sock", kind, i));
        if !p.exists() {
            return Ok(p);
        }
    }
    Err(Error::new_with_message(
        ErrorKind::ServerCreationFailure,
        "cannot find any free socket paths",
    ))
}

fn find_or_autostart_server(
    handle: &Handle,
    socket: Option<&OsStr>,
    config: Arc<config::Config>,
) -> Result<UnixStream, Error> {
    if let Some(socket) = find_server_socket(handle, socket, config.clone()) {
        return Ok(socket);
    }
    autospawn_server(config.clone())?;
    match find_server_socket(handle, socket, config) {
        Some(s) => Ok(s),
        None => Err(Error::new(ErrorKind::SocketConnectionFailure)),
    }
}

async fn credentials_all_vaults(
    creds: &credential::CredentialClient,
) -> Result<Vec<credential::CredentialVault>, credential::CredentialError> {
    let stores = creds.list_stores().await?;
    let mut vaults = Vec::new();
    for store in stores {
        vaults.extend(store.list_vaults().await?)
    }
    Ok(vaults)
}

enum GitCredentialOperation {
    Get,
    Store,
    Erase,
}

fn dispatch_credential_script(
    config: Arc<config::Config>,
    main: &ArgMatches,
    _m: &ArgMatches,
) -> Result<(), Error> {
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    runtime.block_on(async {
        let client = client::Client::new(config);
        match socket
            .peer_addr()
            .ok()
            .and_then(|x| x.as_pathname().map(|x| x.to_owned()))
        {
            Some(name) => debug!(logger, "Connecting to socket {}", escape(path(&*name))),
            None => debug!(logger, "Connecting to anonymous socket"),
        }
        let conn = client.connect_to_socket(socket, false).await?;
        let _ = conn.negotiate_default_version().await;
        let _ = conn.auth_external().await;
        let runner = crate::credential::script::ScriptRunner::new(
            conn.clone(),
            tokio::io::stdin(),
            tokio::io::stdout(),
        )
        .await;
        let mut runner = match runner {
            Ok(runner) => runner,
            Err(e) => {
                return Err(Error::new_full(
                    ErrorKind::CredentialError,
                    Box::new(e),
                    "error initializing credential client",
                ))
            }
        };
        loop {
            match runner.run_command().await {
                Ok(false) => break,
                Ok(true) => continue,
                Err(e) => {
                    return Err(Error::new_full(
                        ErrorKind::ScriptError,
                        Box::new(e),
                        "error parsing script input",
                    ))
                }
            }
        }
        Ok(())
    })
}

fn dispatch_credential_git(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    use credential::CredentialHandle;

    let op = match m.subcommand() {
        ("get", Some(_)) => GitCredentialOperation::Get,
        ("store", Some(_)) => GitCredentialOperation::Store,
        ("erase", Some(_)) => GitCredentialOperation::Erase,
        _ => return Err(Error::new(ErrorKind::Unimplemented)),
    };
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    runtime.block_on(async {
        let client = client::Client::new(config);
        match socket
            .peer_addr()
            .ok()
            .and_then(|x| x.as_pathname().map(|x| x.to_owned()))
        {
            Some(name) => logger.debug(&format!("Connecting to socket {}", escape(path(&*name)))),
            None => logger.debug("Connecting to anonymous socket"),
        }
        let conn = client.connect_to_socket(socket, false).await?;
        let _ = conn.negotiate_default_version().await;
        let _ = conn.auth_external().await;
        let creds = credential::CredentialClient::new(conn).await?;

        let stdin = Arc::new(Mutex::new(io::stdin()));
        let stdout = Arc::new(Mutex::new(io::stdout()));
        let handler = GitProtocolHandler::new(stdin, stdout, Some("git"), Some("api"), None);
        match op {
            GitCredentialOperation::Get => {
                let rhandler = handler.clone();
                let req = match tokio::task::spawn_blocking(|| rhandler.parse_fill_request()).await
                {
                    Ok(Ok(req)) => req,
                    Ok(Err(e)) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error parsing credential input",
                        ))
                    }
                    Err(e) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error parsing credential input",
                        ))
                    }
                };
                let vaults = match credentials_all_vaults(&creds).await {
                    Ok(vaults) => vaults,
                    Err(e) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error acquiring credential vaults",
                        ))
                    }
                };
                for vault in vaults {
                    match vault
                        .search_entry(&req, StoreSearchRecursionLevel::Boolean(true))
                        .await
                    {
                        Ok(Some(cred)) => {
                            let rhandler = handler.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                rhandler.send_fill_response(Some(&cred))
                            })
                            .await;
                            return Ok(());
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            return Err(Error::new_full(
                                ErrorKind::CredentialError,
                                Box::new(e),
                                "error searching credentials",
                            ))
                        }
                    };
                }
                let _ = tokio::task::spawn_blocking(|| handler.send_fill_response(None)).await;
                Ok(())
            }
            kind => {
                let rhandler = handler.clone();
                let cred = match tokio::task::spawn_blocking(|| {
                    rhandler.parse_approve_reject_request(true)
                })
                .await
                {
                    Ok(Ok(Some(cred))) => cred,
                    Ok(Ok(None)) => {
                        return Err(Error::new_with_message(
                            ErrorKind::CredentialError,
                            "error parsing credential input: missing secret",
                        ))
                    }
                    Ok(Err(e)) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error parsing credential input",
                        ))
                    }
                    Err(e) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error parsing credential input",
                        ))
                    }
                };
                let vaults = match credentials_all_vaults(&creds).await {
                    Ok(vaults) => vaults,
                    Err(e) => {
                        return Err(Error::new_full(
                            ErrorKind::CredentialError,
                            Box::new(e),
                            "error acquiring credential vaults",
                        ))
                    }
                };
                match vaults.first() {
                    Some(vault) => {
                        let res = match kind {
                            GitCredentialOperation::Store => vault.put_entry(&cred).await,
                            GitCredentialOperation::Erase => vault.delete_entry(&cred).await,
                            GitCredentialOperation::Get => unreachable!(),
                        };
                        match (res, kind) {
                            (Ok(()), _) => Ok(()),
                            (Err(e), GitCredentialOperation::Store) => Err(Error::new_full(
                                ErrorKind::CredentialError,
                                Box::new(e),
                                "error putting entry",
                            )),
                            (Err(e), GitCredentialOperation::Erase) => Err(Error::new_full(
                                ErrorKind::CredentialError,
                                Box::new(e),
                                "error deleting entry",
                            )),
                            (Err(_), GitCredentialOperation::Get) => unreachable!(),
                        }
                    }
                    None => Err(Error::new_with_message(
                        ErrorKind::CredentialError,
                        "error acquiring credential vaults: no credential vaults found",
                    )),
                }
            }
        }
    })
}

fn dispatch_credential(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    match m.subcommand() {
        ("script", Some(m)) => dispatch_credential_script(config, main, m),
        ("git", Some(m)) => dispatch_credential_git(config, main, m),
        _ => Err(Error::new(ErrorKind::Unimplemented)),
    }
}

fn dispatch_server(
    config: Arc<config::Config>,
    _main: &ArgMatches,
    _m: &ArgMatches,
) -> Result<(), Error> {
    let logger = config.logger();
    logger.trace("Starting server");
    let server = server::Server::new(config);
    server.run()
}

fn dispatch_query_test_connection(
    config: Arc<config::Config>,
    main: &ArgMatches,
    _m: &ArgMatches,
) -> Result<(), Error> {
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    runtime.block_on(async {
        let client = client::Client::new(config);
        match socket.peer_addr() {
            Ok(addr) => match addr.as_pathname() {
                Some(p) => logger.message(&format!("Testing socket {}", escape(path(p)))),
                None => logger.message("Testing anonymous socket"),
            },
            Err(_) => {
                logger.message("Testing SSH socket");
            }
        }
        let conn = match client.connect_to_socket(socket, true).await {
            Ok(conn) => {
                logger.message("Connection: ok");
                conn
            }
            Err(e) => {
                logger.message(&format!("Connection: FAILED: {}", e));
                return Err(e);
            }
        };
        match conn.ping().await {
            Ok(_) => logger.message("Ping: ok"),
            Err(e) => logger.message(&format!("Ping: FAILED: {}", e)),
        }
        match conn.capability().await {
            Ok(resp) => {
                logger.message("Capability: ok");
                for version in resp.version {
                    logger.message(&format!("Capability: version {} supported", version));
                }
                for capa in resp.capabilities {
                    match capa {
                        (name, Some(arg)) => logger.message(&format!(
                            "Capability: capability {}={} supported",
                            escape(name),
                            escape(arg)
                        )),
                        (name, None) => logger.message(&format!(
                            "Capability: capability {} supported",
                            escape(name)
                        )),
                    }
                }
                if let Some(user_agent) = resp.user_agent {
                    logger.message(&format!("Capability: user-agent: {}", user_agent));
                }
            }
            Err(e) => logger.message(&format!("Capability: FAILED: {}", e)),
        }
        match conn.negotiate_default_version().await {
            Ok(_) => {
                logger.message("Version negotiation: ok");
            }
            Err(e) => logger.message(&format!("Version negotiation: FAILED: {}", e)),
        }
        match conn.auth_external().await {
            Ok(_) => {
                logger.message("Authenticate EXTERNAL: ok");
                Ok(())
            }
            Err(e) => {
                logger.message(&format!("Authenticate EXTERNAL: FAILED: {}", e));
                Err(e)
            }
        }
    })
}

fn dispatch_query(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    match m.subcommand() {
        ("test-connection", Some(m)) => dispatch_query_test_connection(config, main, m),
        _ => Err(Error::new(ErrorKind::Unimplemented)),
    }
}

fn dispatch_proxy(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    let args: Vec<OsString> = match m.values_of_os("arg") {
        Some(args) => args.map(|x| x.to_owned()).collect(),
        _ => return Err(Error::new(ErrorKind::MissingArguments)),
    };
    if args.is_empty() {
        return Err(Error::new(ErrorKind::MissingArguments));
    }
    let ssh_socket = match std::env::var_os("SSH_AUTH_SOCK") {
        Some(env) => env,
        None => {
            return Err(Error::new_with_message(
                ErrorKind::NoSuchSocket,
                "SSH_AUTH_SOCK is not set",
            ))
        }
    };
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    let res: Result<i32, Error> = runtime.block_on(async move {
        let addr = socket.peer_addr().unwrap();
        let ours = addr.as_pathname().unwrap();
        let multiplex = find_vacant_socket(config.clone(), "ssh")?;

        trace!(logger, "using {} as SSH socket", escape(path(&*multiplex)));
        let proxy = ssh_proxy::ProxyListener::new(
            config,
            ssh_socket.into(),
            ours.into(),
            multiplex.clone(),
        )
        .map_err(|_| Error::new(ErrorKind::SocketConnectionFailure))?;
        tokio::spawn(async move {
            let _ = proxy.run_server().await;
        });
        let ssh_sock = multiplex.clone();
        let join = tokio::task::spawn_blocking(move || {
            let res = std::process::Command::new(args[0].clone())
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .env("SSH_AUTH_SOCK", OsString::from(&ssh_sock))
                .args(&args[1..])
                .spawn();
            match res {
                Ok(mut child) => match child.wait() {
                    Ok(st) => st.code().unwrap_or(127),
                    Err(_) => 127,
                },
                Err(_) => 127,
            }
        });
        let res = join.await.unwrap();
        let _ = std::fs::remove_file(&multiplex);
        Ok(res)
    });
    std::process::exit(res?);
}

enum ProxyType {
    Listener(fs_proxy::ProxyListener),
    ProxyFromBoundSocket(tokio::net::UnixListener),
}

fn dispatch_mount(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    let (prefix, desc, pproto, autoargs): (_, _, _, Option<&[&str]>) = match m.value_of("type") {
        Some("9p") | None => ("9p", "9P", fs_proxy::ProxyProtocol::P9P, None),
        Some("sftp") => (
            "sftp",
            "SFTP",
            fs_proxy::ProxyProtocol::SFTP,
            Some(&["sshfs", "-o", "passive", ":/"]),
        ),
        Some(p) => {
            return Err(Error::new_with_message(
                ErrorKind::UnknownProtocolType,
                format!("unknown protocol {}", p),
            ))
        }
    };
    let args: Vec<OsString> = match (m.is_present("auto"), autoargs, m.values_of_os("arg")) {
        (true, Some(autoargs), Some(args)) if args.len() == 1 => autoargs
            .iter()
            .cloned()
            .map(|arg| OsString::from(arg.to_owned()))
            .chain(args.map(|x| x.to_owned()))
            .collect(),
        (true, None, _) => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                format!("--auto cannot be used with mountpoints of type {}", prefix),
            ))
        }
        (true, _, None) => {
            return Err(Error::new_with_message(
                ErrorKind::MissingArguments,
                "a destination mountpoint is required",
            ))
        }
        (true, _, Some(_)) => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                "only a single argument (a destination mountpoint) may be provided",
            ));
        }
        (false, _, Some(args)) => args.map(|x| x.to_owned()).collect(),
        _ => return Err(Error::new(ErrorKind::MissingArguments)),
    };
    if args.is_empty() {
        return Err(Error::new(ErrorKind::MissingArguments));
    }
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    let res: Result<i32, Error> = runtime.block_on(async move {
        let target = m.value_of_os("target").unwrap();
        let addr = socket.peer_addr().unwrap();
        let ours = addr.as_pathname();
        let fs_sock = find_vacant_socket(config.clone(), prefix)?;
        let fs_sock_loc = fs_sock.clone();
        trace!(
            logger,
            "using {} as {} socket",
            escape(path(&*fs_sock)),
            desc
        );
        let want_socket = if m.is_present("socket") {
            true
        } else if m.is_present("fd") || autoargs.is_some() {
            false
        } else {
            error!(logger, "one of --socket or --fd is required");
            return Err(Error::new(ErrorKind::MissingArguments));
        };
        let dest: Bytes = target.as_bytes().to_vec().into();
        let proxy = match ours {
            Some(ours) => ProxyType::Listener(
                fs_proxy::ProxyListener::new(
                    config.clone(),
                    fs_sock.clone(),
                    ours.into(),
                    dest.clone(),
                    pproto,
                )
                .map_err(|_| Error::new(ErrorKind::SocketConnectionFailure))?,
            ),
            None => {
                let psock = tokio::net::UnixListener::bind(&fs_sock).map_err(|e| {
                    Error::new_full(ErrorKind::SocketBindFailure, e, "unable to bind 9P socket")
                })?;
                ProxyType::ProxyFromBoundSocket(psock)
            }
        };
        let handle = tokio::spawn(async move {
            match proxy {
                ProxyType::Listener(proxy) => {
                    if !want_socket {
                        let _ = proxy.run_server_once().await;
                    } else {
                        let _ = proxy.run_server().await;
                    }
                }
                ProxyType::ProxyFromBoundSocket(psock) => {
                    let _ = socket.set_nonblocking(true);
                    let conn = Connection::new(
                        config.clone(),
                        None,
                        tokio::net::UnixStream::from_std(socket).unwrap(),
                        false,
                    );
                    loop {
                        if let Ok((req, _)) = psock.accept().await {
                            let proxy = fs_proxy::Proxy::new_from_connection(
                                config.clone(),
                                req,
                                conn.clone(),
                                dest.clone(),
                                pproto,
                            );
                            let _ = proxy.run_server().await;
                            if !want_socket {
                                break;
                            }
                        }
                    }
                }
            }
        });
        let join = tokio::task::spawn_blocking(move || {
            let mut res = std::process::Command::new(args[0].clone());
            res.stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            if want_socket {
                match pproto {
                    fs_proxy::ProxyProtocol::P9P => res.env("P9P_SOCK", OsString::from(&fs_sock)),
                    fs_proxy::ProxyProtocol::SFTP => {
                        res.env("LAWN_SFTP_SOCK", OsString::from(&fs_sock))
                    }
                };
            } else {
                use std::os::unix::io::{FromRawFd, IntoRawFd};

                let sock = match std::os::unix::net::UnixStream::connect(fs_sock) {
                    Ok(sock) => sock,
                    Err(e) => {
                        error!(logger, "failed to connect to socket: {}", e);
                        return 127;
                    }
                };
                let fd = sock.into_raw_fd();
                res.stdin(unsafe { Stdio::from_raw_fd(fd) });
                res.stdout(unsafe { Stdio::from_raw_fd(fd) });
            }
            let res = res.args(&args[1..]).spawn();
            match res {
                Ok(mut child) => match child.wait() {
                    Ok(st) => st.code().unwrap_or(127),
                    Err(_) => 127,
                },
                Err(_) => 127,
            }
        });
        let _ = handle.await;
        let res = join.await.unwrap();
        let _ = std::fs::remove_file(&fs_sock_loc);
        Ok(res)
    });
    std::process::exit(res?);
}

fn dispatch_clip(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    let op = match (m.is_present("copy"), m.is_present("paste")) {
        (true, false) => ClipboardChannelOperation::Copy,
        (false, true) => ClipboardChannelOperation::Paste,
        _ => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                "exactly one of -i or -o is required",
            ))
        }
    };
    let target = match (m.is_present("primary"), m.is_present("clipboard")) {
        (true, false) => Some(ClipboardChannelTarget::Primary),
        (false, true) => Some(ClipboardChannelTarget::Clipboard),
        (false, false) => None,
        _ => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                "at most one of -p and -b is permitted",
            ))
        }
    };
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    let res = runtime.block_on(async move {
        let client = client::Client::new(config);
        match socket
            .peer_addr()
            .ok()
            .and_then(|x| x.as_pathname().map(|x| x.to_owned()))
        {
            Some(name) => logger.debug(&format!("Connecting to socket {}", escape(path(&*name)))),
            None => logger.debug("Connecting to anonymous socket"),
        }
        let conn = client.connect_to_socket(socket, false).await?;
        let _ = conn.negotiate_default_version().await;
        let _ = conn.auth_external().await;
        conn.run_clipboard(tokio::io::stdin(), tokio::io::stdout(), op, target)
            .await
    })?;
    std::process::exit(res);
}

fn dispatch_run(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    let args: Vec<Bytes> = match m.values_of_os("arg") {
        Some(args) => args.map(|x| x.as_bytes().to_vec().into()).collect(),
        None => return Err(Error::new(ErrorKind::MissingArguments)),
    };
    let logger = config.logger();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let socket =
        find_or_autostart_server(runtime.handle(), main.value_of_os("socket"), config.clone())?;
    let res = runtime.block_on(async move {
        let client = client::Client::new(config);
        match socket
            .peer_addr()
            .ok()
            .and_then(|x| x.as_pathname().map(|x| x.to_owned()))
        {
            Some(name) => logger.debug(&format!("Connecting to socket {}", escape(path(&*name)))),
            None => logger.debug("Connecting to anonymous socket"),
        }
        let conn = client.connect_to_socket(socket, false).await?;
        let _ = conn.negotiate_default_version().await;
        let _ = conn.auth_external().await;
        conn.run_command(
            &args,
            tokio::io::stdin(),
            tokio::io::stdout(),
            tokio::io::stderr(),
        )
        .await
    })?;
    std::process::exit(res);
}

fn dispatch(verbosity: &mut i32) -> Result<(), Error> {
    let matches = App::new("lawn")
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .multiple(true)
                .help("Make the command more verbose"),
        )
        .arg(
            Arg::with_name("quiet")
                .long("quiet")
                .short("q")
                .multiple(true)
                .help("Make the command less verbose"),
        )
        .arg(Arg::with_name("socket").long("socket").takes_value(true).help("Specify the path to the Lawn socket"))
        .arg(Arg::with_name("no-detach").long("no-detach").help("Do not detach from the terminal when starting a server"))
        .subcommand(App::new("server").about("Start a server on the root machine"))
        .subcommand(App::new("query").about("Query information about Lawn").subcommand(App::new("test-connection").about("Test that a connection can be made and is basically functional")))
        .subcommand(
            App::new("clip")
                .about("Copy to and paste from the clipboard")
                .arg(Arg::with_name("copy").long("copy").short("i").help("Copy standard input to the clipboard"))
                .arg(Arg::with_name("paste").long("paste").short("o").help("Paste the clipboard to the standard output"))
                .arg(Arg::with_name("primary").long("primary").short("p").help("Use the PRIMARY selection on X11"))
                .arg(Arg::with_name("clipboard").long("clipboard").short("b").help("Use the CLIPBOARD selection on X11 or the regular clipboard on other platforms")),
        )
        .subcommand(
            App::new("credential")
                .about("Query credentials")
                .subcommand(App::new("script")
                            .about("Take scripting commands from standard input")
                            )
                .subcommand(App::new("git")
                            .about("Operate as a Git credential helper")
                            .subcommand(App::new("get")
                                        .about("Fill credentials using the Git credential protocol")
                                    )
                            .subcommand(App::new("store")
                                        .about("Approve credentials using the Git credential protocol")
                                    )
                            .subcommand(App::new("erase")
                                        .about("Reject credentials using the Git credential protocol")
                                    )
                            )
        )
        .subcommand(
            App::new("proxy")
                .about("Create an SSH agent suitable which can be used for Lawn commands")
                .arg(Arg::with_name("ssh").long("ssh"))
                .arg(Arg::with_name("arg").multiple(true).help("Command and arguments to run (usually \"ssh -A\")")),
        )
        .subcommand(
            App::new("mount")
                .about("Provide access to a file system mount")
                .arg(Arg::with_name("socket").long("socket").help("Use a socket to expose the mount"))
                .arg(Arg::with_name("fd").long("fd").help("Expose the mount to the command using standard input and output"))
                .arg(
                    Arg::with_name("type")
                        .long("type")
                        .takes_value(true)
                        .value_name("PROTOCOL")
                        .help("Protocol to use to access the mount: \"9p\" (default) or \"sftp\""),
                )
                .arg(Arg::with_name("auto").long("auto").help("Automatically guess a suitable program to mount"))
                .arg(Arg::with_name("target").required(true).help("Name of the mount point to mount"))
                .arg(Arg::with_name("arg").multiple(true).required(true).help("With --auto, the path to mount on; otherwise, the command to run")),
        )
        .subcommand(App::new("run").about("Run a command").arg(Arg::with_name("arg").multiple(true).help("Name of the command and its arguments")))
        .get_matches();
    *verbosity = matches.occurrences_of("verbose") as i32 - matches.occurrences_of("quiet") as i32;
    let config = config(*verbosity)?;
    if matches.is_present("no-detach") {
        config.set_detach(false);
    }
    match matches.subcommand() {
        ("credential", Some(m)) => dispatch_credential(config, &matches, m),
        ("server", Some(m)) => dispatch_server(config, &matches, m),
        ("query", Some(m)) => dispatch_query(config, &matches, m),
        ("clip", Some(m)) => dispatch_clip(config, &matches, m),
        ("mount", Some(m)) => dispatch_mount(config, &matches, m),
        ("proxy", Some(m)) => dispatch_proxy(config, &matches, m),
        ("run", Some(m)) => dispatch_run(config, &matches, m),
        _ => Err(Error::new(ErrorKind::Unimplemented)),
    }
}

fn main() {
    let mut verbosity = 0;
    match dispatch(&mut verbosity) {
        Ok(()) => (),
        Err(e) => {
            if verbosity > -2 {
                eprintln!("error: {}", e);
            }
            std::process::exit(e.into());
        }
    }
}
