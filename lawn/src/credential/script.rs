#![allow(clippy::enum_variant_names)]

use crate::client::Connection;
use crate::credential::{CredentialClient, CredentialError, CredentialObject};
use crate::error::ExtendedError;
use crate::serializer::script::{self, ScriptDeserializer, ScriptEncoder};
use bytes::Bytes;
use std::borrow::{Borrow, Cow};
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};

pub struct ScriptRunner<
    R: AsyncReadExt + Unpin + Send + Sync,
    W: AsyncWriteExt + Unpin + Send + Sync,
> {
    reader: BufReader<R>,
    writer: BufWriter<W>,
    client: CredentialClient,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    CredentialError(#[from] CredentialError),
    #[error("{0}")]
    DeserializerError(#[from] script::Error),
    #[error("{0}")]
    IOError(#[from] io::Error),
    #[error("unknown command: {0}")]
    UnknownCommand(String),
}

impl ExtendedError for Error {
    fn error_types(&self) -> Cow<'static, [Cow<'static, str>]> {
        Cow::Borrowed(&[Cow::Borrowed("script-error")])
    }
    fn error_tag(&self) -> Cow<'static, str> {
        match self {
            Self::CredentialError(..) => "credential-error".into(),
            Self::DeserializerError(..) => "deserialization-error".into(),
            Self::IOError(e) => format!("{}", lawn_constants::Error::from(e)).into(),
            Self::UnknownCommand(..) => "unknown-command".into(),
        }
    }
}

impl<R: AsyncReadExt + Unpin + Send + Sync, W: AsyncWriteExt + Unpin + Send + Sync>
    ScriptRunner<R, W>
{
    pub async fn new(conn: Arc<Connection>, reader: R, writer: W) -> Result<Self, Error> {
        Ok(Self {
            client: CredentialClient::new(conn).await?,
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
        })
    }

    pub async fn run_command(&mut self) -> Result<bool, Error> {
        let mut v = Vec::new();
        let val = match self.reader.read_until(b'\n', &mut v).await {
            Ok(0) => return Ok(false),
            Ok(_) => {
                if let Some(b'\n') = v.last() {
                    &v[0..v.len() - 1]
                } else {
                    return Err(script::Error::MissingNewline.into());
                }
            }
            Err(e) => return Err(e.into()),
        };
        let sd = ScriptDeserializer::new(val);
        let (tag, msg) = sd.parse_owned::<(String, String)>()?;
        match self.dispatch(tag.borrow(), msg.borrow(), &sd).await {
            Ok(messages) => {
                for message in messages {
                    self.writer.write_all(tag.as_bytes()).await?;
                    self.writer.write_all(b" ok ").await?;
                    for (i, val) in message.iter().enumerate() {
                        self.writer.write_all(val.as_ref()).await?;
                        if i != message.len() - 1 {
                            self.writer.write_all(b" ").await?;
                        }
                    }
                    self.writer.write_all(b"\n").await?;
                }
                let _ = self.writer.flush().await;
                Ok(true)
            }
            Err(e) => {
                let se = ScriptEncoder::new();
                self.writer.write_all(tag.as_bytes()).await?;
                self.writer.write_all(b" err ").await?;
                let error_types = e.error_types();
                let error_types: &[Cow<'static, str>] = error_types.borrow();
                let error_types = error_types.join(":");
                self.writer.write_all(error_types.as_bytes()).await?;
                self.writer.write_all(b" ").await?;
                self.writer.write_all(e.error_tag().as_bytes()).await?;
                self.writer.write_all(b" ").await?;
                self.writer
                    .write_all(se.encode(&format!("{}", e)).borrow())
                    .await?;
                self.writer.write_all(b"\n").await?;
                let _ = self.writer.flush().await;
                Ok(true)
            }
        }
    }

    async fn dispatch<'de>(
        &self,
        _tag: &str,
        msg: &str,
        de: &'de ScriptDeserializer<'de>,
    ) -> Result<Vec<Vec<Bytes>>, Error> {
        let se = ScriptEncoder::new();
        match msg {
            "mkdir" => {
                let path: Cow<'de, [u8]> = de.parse()?;
                let mut pieces = path.rsplitn(3, |b| *b == b'/');
                let empty = pieces
                    .next()
                    .ok_or(Error::CredentialError(CredentialError::NotADirectory))?;
                if !empty.is_empty() {
                    return Err(Error::CredentialError(CredentialError::NotADirectory));
                }
                let component = pieces
                    .next()
                    .ok_or(Error::CredentialError(CredentialError::InvalidPath))?;
                let dir = pieces
                    .next()
                    .ok_or(Error::CredentialError(CredentialError::InvalidPath))?;
                // Add the trailing slash back.
                let dir = Bytes::copy_from_slice(&path[0..=dir.len()]);
                let obj = self.client.get_object(dir).await?;
                match obj {
                    Some(CredentialObject::Store(s)) => {
                        s.create_vault(component).await?;
                    }
                    Some(CredentialObject::Vault(v)) => {
                        v.create_directory(component).await?;
                    }
                    Some(CredentialObject::Directory(d)) => {
                        d.create_directory(component).await?;
                    }
                    None => return Err(Error::CredentialError(CredentialError::NotFound)),
                    _ => return Err(Error::CredentialError(CredentialError::InvalidPath)),
                };
                Ok(vec![vec![
                    se.encode_to_bytes(b"mkdir" as &[u8]),
                    se.encode_to_bytes::<[u8]>(path.borrow()),
                ]])
            }
            "noop" => Ok(vec![vec![se.encode_to_bytes(b"noop" as &[u8])]]),
            other => Err(Error::UnknownCommand(other.to_owned())),
        }
    }
}
