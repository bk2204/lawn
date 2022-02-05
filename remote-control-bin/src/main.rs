extern crate bytes;
extern crate clap;
extern crate daemonize;
extern crate hex;
extern crate libc;
extern crate remote_control_protocol;
extern crate tokio;

use crate::encoding::{escape, osstr};
use bytes::Bytes;
use clap::{App, Arg, ArgMatches};
use remote_control_protocol::config::Logger;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::Arc;

mod channel;
mod client;
mod config;
mod encoding;
mod error;
mod server;
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
        path.push("remote-control");
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

fn dispatch_server(config: Arc<config::Config>, m: &ArgMatches) -> Result<(), Error> {
    if m.is_present("no-detach") {
        config.set_detach(false);
    }
    let logger = config.logger();
    logger.trace("Starting server");
    let server = server::Server::new(config);
    server.run()
}

fn dispatch_query_test_connection(
    config: Arc<config::Config>,
    m: &ArgMatches,
) -> Result<(), Error> {
    let socket = m.value_of_os("socket").unwrap();
    let logger = config.logger();
    let client = client::Client::new(config);
    logger.trace("Starting runtime");
    let runtime = runtime();
    runtime.block_on(async {
        logger.message(&format!("Testing socket {}", escape(osstr(socket))));
        let conn = match client.connect(socket, true).await {
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
            }
            Err(e) => logger.message(&format!("Authenticate EXTERNAL: FAILED: {}", e)),
        }
        Ok(())
    })
}

fn dispatch_query(config: Arc<config::Config>, m: &ArgMatches) -> Result<(), Error> {
    match m.subcommand() {
        ("test-connection", Some(m)) => dispatch_query_test_connection(config, m),
        _ => Err(Error::new(ErrorKind::Unimplemented)),
    }
}

fn dispatch_clipboard(_config: Arc<config::Config>, _m: &ArgMatches) -> Result<(), Error> {
    Err(Error::new(ErrorKind::Unimplemented))
}

fn dispatch_run(config: Arc<config::Config>, m: &ArgMatches) -> Result<(), Error> {
    let args: Vec<Bytes> = match m.values_of_os("arg") {
        Some(args) => args.map(|x| x.as_bytes().to_vec().into()).collect(),
        None => return Err(Error::new(ErrorKind::MissingArguments)),
    };
    let logger = config.logger();
    let client = client::Client::new(config);
    let socket = m.value_of_os("socket").unwrap();
    logger.trace("Starting runtime");
    let runtime = runtime();
    let res = runtime.block_on(async move {
        logger.debug(&format!("Connecting to socket {}", escape(osstr(socket))));
        let conn = client.connect(socket, false).await?;
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

fn dispatch() -> Result<(), Error> {
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
        .subcommand(App::new("server").arg(Arg::with_name("no-detach").long("no-detach")))
        .subcommand(
            App::new("query").subcommand(
                App::new("test-connection").arg(
                    Arg::with_name("socket")
                        .long("socket")
                        .takes_value(true)
                        .required(true),
                ),
            ),
        )
        .subcommand(App::new("clipboard"))
        .subcommand(
            App::new("run")
                .arg(Arg::with_name("arg").multiple(true))
                .arg(
                    Arg::with_name("socket")
                        .long("socket")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();
    let verbosity =
        matches.occurrences_of("verbose") as i32 - matches.occurrences_of("quiet") as i32;
    let config = config(verbosity)?;
    match matches.subcommand() {
        ("server", Some(m)) => dispatch_server(config, m),
        ("query", Some(m)) => dispatch_query(config, m),
        ("clipboard", Some(m)) => dispatch_clipboard(config, m),
        ("run", Some(m)) => dispatch_run(config, m),
        _ => Err(Error::new(ErrorKind::Unimplemented)),
    }
}

fn main() {
    match dispatch() {
        Ok(()) => (),
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(e.into());
        }
    }
}
