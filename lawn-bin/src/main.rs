extern crate bytes;
extern crate clap;
extern crate daemonize;
extern crate hex;
extern crate lawn_protocol;
extern crate libc;
extern crate num_derive;
extern crate tokio;

use crate::encoding::{escape, osstr, path};
use bytes::Bytes;
use clap::{App, Arg, ArgMatches};
use lawn_protocol::config::Logger;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

mod channel;
mod client;
mod config;
mod encoding;
mod error;
mod server;
mod ssh_proxy;
mod task;
mod template;
mod unix;

use error::{Error, ErrorKind};

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

fn find_server_socket(socket: Option<&OsStr>, config: Arc<config::Config>) -> Option<UnixStream> {
    let logger = config.logger();
    if let Some(socket) = socket {
        trace!(logger, "trying specified socket {}", escape(osstr(socket)));
        return match UnixStream::connect(&socket) {
            Ok(sock) => Some(sock),
            Err(_) => None,
        };
    }
    if let Some(path) = std::env::var_os("SSH_AUTH_SOCK") {
        trace!(logger, "trying SSH socket {}", escape(osstr(&*path)));
        match UnixStream::connect(path) {
            Ok(sock) => {
                let logger = logger.clone();
                let config = config.clone();
                let res = task::block_on_async(async move {
                    trace!(logger, "SSH socket: performing client probe");
                    match ssh_proxy::Proxy::client_probe(config.clone(), sock).await {
                        Ok(sock) => {
                            let config = config.clone();
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
                            trace!(logger, "failed to connect to SSH socket");
                            Err(e)
                        }
                    }
                });
                if let Ok(sock) = res {
                    return Some(sock.into_std().unwrap());
                }
            }
            Err(e) => {
                trace!(logger, "SSH socket: failed to connect: {}", e);
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
                trace!(
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
                    trace!(
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
            trace!(logger, "autospawning server");
            let server = server::Server::new(config);
            if let Err(e) = server.run_forked() {
                error!(logger, "failed to autospawn server: {}", e);
                Err(e)
            } else {
                Ok(())
            }
        }
        Ok(false) => {
            trace!(logger, "not root, not autospawning server");
            Err(Error::new(ErrorKind::NotRootMachine))
        }
        Err(e) => {
            error!(
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
    socket: Option<&OsStr>,
    config: Arc<config::Config>,
) -> Result<UnixStream, Error> {
    if let Some(socket) = find_server_socket(socket, config.clone()) {
        return Ok(socket);
    }
    autospawn_server(config.clone())?;
    match find_server_socket(socket, config) {
        Some(s) => Ok(s),
        None => Err(Error::new(ErrorKind::SocketConnectionFailure)),
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
    runtime.block_on(async {
        let socket = find_or_autostart_server(main.value_of_os("socket"), config.clone())?;
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
            }
            Err(e) => logger.message(&format!("Capability: FAILED: {}", e)),
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
    let res: Result<i32, Error> = runtime.block_on(async move {
        let socket = find_or_autostart_server(main.value_of_os("socket"), config.clone())?;
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

fn dispatch_clipboard(
    _config: Arc<config::Config>,
    _main: &ArgMatches,
    _m: &ArgMatches,
) -> Result<(), Error> {
    Err(Error::new(ErrorKind::Unimplemented))
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
    let res = runtime.block_on(async move {
        let socket = find_or_autostart_server(main.value_of_os("socket"), config.clone())?;
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
    let matches = App::new("remctrl")
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .multiple(true),
        )
        .arg(
            Arg::with_name("quiet")
                .long("quiet")
                .short("q")
                .multiple(true),
        )
        .arg(Arg::with_name("socket").long("socket").takes_value(true))
        .arg(Arg::with_name("no-detach").long("no-detach"))
        .subcommand(App::new("server"))
        .subcommand(App::new("query").subcommand(App::new("test-connection")))
        .subcommand(App::new("clipboard"))
        .subcommand(
            App::new("proxy")
                .arg(Arg::with_name("ssh").long("ssh"))
                .arg(Arg::with_name("arg").multiple(true)),
        )
        .subcommand(App::new("run").arg(Arg::with_name("arg").multiple(true)))
        .get_matches();
    *verbosity = matches.occurrences_of("verbose") as i32 - matches.occurrences_of("quiet") as i32;
    let config = config(*verbosity)?;
    if matches.is_present("no-detach") {
        config.set_detach(false);
    }
    match matches.subcommand() {
        ("server", Some(m)) => dispatch_server(config, &matches, m),
        ("query", Some(m)) => dispatch_query(config, &matches, m),
        ("clipboard", Some(m)) => dispatch_clipboard(config, &matches, m),
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
