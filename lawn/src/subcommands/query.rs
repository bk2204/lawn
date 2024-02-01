use crate::client;
use crate::config::{self, SerializedLogger};
use crate::encoding::{escape, osstr};
use crate::error::{Error, ErrorKind};
use crate::serializer::script::ScriptEncoder;
use crate::template::{self, Template, TemplateContext};
use bytes::Bytes;
use clap::ArgMatches;
use format_bytes::format_bytes;
use lawn_constants::logger::LogFormat;
use lawn_constants::logger::Logger as LoggerTrait;
use lawn_protocol::protocol::{CredentialStoreElement, TemplateServerContextBodyWithBody};
use serde::Serialize;
use std::borrow::Borrow;
use std::sync::Arc;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TemplateContextResponse<'a, T> {
    context: &'a TemplateServerContextBodyWithBody<T>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TemplateContextFormatResponse {
    data: Bytes,
}

fn format_template<T>(
    ctx: TemplateServerContextBodyWithBody<T>,
    pattern: &[u8],
) -> Result<Bytes, template::Error> {
    let ctx: TemplateContext = ctx.into();
    Template::new(pattern).expand(&ctx)
}

pub fn dispatch_query_context(
    config: Arc<config::Config>,
    main: &ArgMatches,
    m: &ArgMatches,
) -> Result<(), Error> {
    let logger = config.logger();
    trace!(logger, "Starting runtime");
    let runtime = crate::runtime();
    let mut socket = crate::find_or_autostart_server(
        runtime.handle(),
        main.value_of_os("socket"),
        config.clone(),
    )?;
    match m.value_of("type") {
        Some("template") | None => (),
        _ => {
            return Err(Error::new_with_message(
                ErrorKind::InvalidArgumentValue,
                r#"invalid argument for --type (only "template" is allowed)"#,
            ))
        }
    }
    let pattern = match (m.is_present("list"), m.value_of("format")) {
        (true, None) => None,
        (false, Some(p)) => Some(p),
        (true, Some(_)) => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                r"at least one of --list or --pattern is required",
            ))
        }
        (_, _) => {
            return Err(Error::new_with_message(
                ErrorKind::IncompatibleArguments,
                r"--list and --pattern are mutually exclusive",
            ))
        }
    };
    let ctxid = match socket.context() {
        Some(ctx) => ctx,
        None => return Err(Error::new_with_message(
            ErrorKind::MissingContext,
            "the LAWN environment variable must be set and have a context to use this subcommand",
        )),
    };
    runtime.block_on(async {
        let client = client::Client::new(config);
        debug!(
            logger,
            "Connecting to {} {}",
            socket.kind(),
            escape(osstr(socket.path()))
        );
        let conn = client
            .connect_to_socket(socket.lawn_socket().unwrap(), false)
            .await?;
        let _ = conn.negotiate_default_version().await;
        let _ = conn.auth_external().await;

        let (kind, ctx) = match conn
            .read_template_context::<CredentialStoreElement>(ctxid)
            .await
        {
            Ok(Some(ctx)) => ctx,
            Ok(None) => {
                return Err(Error::new_with_message(
                    ErrorKind::MissingContext,
                    "the LAWN environment variable contains an invalid context",
                ))
            }
            Err(e) => return Err(e),
        };
        trace!(logger, "query context: found context of kind {:?}", kind);
        // If pattern is None, this is list mode; otherwise, it's pattern mode.
        match (pattern, logger.format()) {
            (None, LogFormat::CBOR) | (None, LogFormat::JSON) => {
                let body = TemplateContextResponse { context: &ctx };
                logger.serialized_message(&body);
                Ok(())
            }
            (None, LogFormat::Scriptable) => {
                let tag = b"_a01";
                if let Some(args) = ctx.args {
                    for arg in args {
                        logger.script_message(Some(tag), &[b"context", b"args", &arg]);
                    }
                }
                let pairs = &[
                    (&ctx.senv, "senv"),
                    (&ctx.cenv, "cenv"),
                    (&ctx.ctxsenv, "ctxsenv"),
                ];
                for (data, kind) in pairs {
                    if let Some(args) = data {
                        for (k, v) in args {
                            logger.script_message(Some(tag), &[b"context", kind.as_bytes(), k, v]);
                        }
                    }
                }
                if let (Some("credential"), Some(body)) = (kind.as_deref(), ctx.body) {
                    logger
                        .script_message(Some(tag), &[b"context", b"template-type", b"credential"]);
                    let se = ScriptEncoder::new();
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"username", se.encode(&body.username).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"secret", se.encode(&body.secret).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"authtype", se.encode(&body.authtype).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"type", se.encode(&body.kind).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"title", se.encode(&body.title).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[
                            b"context",
                            b"description",
                            se.encode(&body.description).borrow(),
                        ],
                    );
                    for loc in body.location {
                        logger.script_message(
                            Some(tag),
                            &[
                                b"context",
                                b"location",
                                se.encode(&loc.protocol).borrow(),
                                se.encode(&loc.host).borrow(),
                                se.encode(&loc.port).borrow(),
                                se.encode(&loc.path).borrow(),
                            ],
                        );
                    }
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"service", se.encode(&body.service).borrow()],
                    );
                    logger.script_message(
                        Some(tag),
                        &[b"context", b"id", se.encode(&body.id).borrow()],
                    );
                }
                Ok(())
            }
            (None, LogFormat::Text) => {
                logger.message("args:");
                if let Some(args) = ctx.args {
                    for arg in args {
                        logger.message_bytes(&format_bytes!(b"\t{}", arg.as_ref()));
                    }
                }
                let pairs = &[
                    (&ctx.senv, "senv"),
                    (&ctx.cenv, "cenv"),
                    (&ctx.ctxsenv, "ctxsenv"),
                ];
                for (data, kind) in pairs {
                    logger.message(&format!("{}:", kind));
                    if let Some(args) = data {
                        for (k, v) in args {
                            logger.message_bytes(&format_bytes!(
                                b"\t{}={}",
                                k.as_ref(),
                                v.as_ref()
                            ));
                        }
                    }
                }
                if let (Some("credential"), Some(body)) = (kind.as_deref(), ctx.body) {
                    if let Some(username) = &body.username {
                        logger.message_bytes(&format_bytes!(b"username={}", username.as_ref()));
                    }
                    if let Some(secret) = &body.secret {
                        logger.message_bytes(&format_bytes!(b"secret={}", secret.as_ref()));
                    }
                    if let Some(authtype) = &body.authtype {
                        logger.message_bytes(&format_bytes!(b"authtype={}", authtype.as_bytes(),));
                    }
                    logger.message_bytes(&format_bytes!(b"type={}", body.kind.as_bytes()));
                    logger.message_bytes(&format_bytes!(b"id={}", body.id.as_ref()));
                    if let Some(title) = body.title {
                        logger.message_bytes(&format_bytes!(b"title={}", title.as_bytes(),));
                    }
                    if let Some(desc) = body.description {
                        logger.message_bytes(&format_bytes!(b"description={}", desc.as_bytes(),));
                    }
                    let mut s = String::with_capacity(128);
                    for loc in body.location {
                        if let (Some(protocol), Some(host)) = (&loc.protocol, &loc.host) {
                            s += &protocol;
                            s += "://";
                            s += &host;
                        }
                        if let Some(port) = loc.port {
                            use std::fmt::Write;

                            s += ":";
                            let _ = write!(s, "{}", port);
                        }
                        s += match &loc.path {
                            Some(path) => path,
                            None => "/",
                        };
                        logger.message(&format!("location={}", s));
                    }
                    if let Some(service) = body.service {
                        logger.message_bytes(&format_bytes!(b"service={}", service.as_bytes()));
                    }
                }
                Ok(())
            }
            (Some(pat), LogFormat::CBOR) | (Some(pat), LogFormat::JSON) => {
                match format_template(ctx, pat.as_bytes()) {
                    Ok(data) => {
                        let body = TemplateContextFormatResponse { data };
                        logger.serialized_message(&body);
                    }
                    Err(e) => logger.serialized_error(&e),
                }
                Ok(())
            }
            (Some(pat), LogFormat::Scriptable) => {
                let tag = b"_a01";
                match format_template(ctx, pat.as_bytes()) {
                    Ok(data) => {
                        logger.script_message(Some(tag), &[b"context", b"format", &data]);
                    }
                    Err(e) => logger.script_error(Some(tag), &e),
                }
                Ok(())
            }
            (Some(pat), LogFormat::Text) => match format_template(ctx, pat.as_bytes()) {
                Ok(data) => {
                    logger.message_bytes(&data);
                    Ok(())
                }
                Err(e) => Err(Error::new_with_cause(ErrorKind::TemplateError, e)),
            },
        }
    })
}
