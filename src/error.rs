///! Error structs for iroh-persist
use std::path::PathBuf;

use iroh::{KeyParsingError, SecretKey};
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PersistError {
    KeyWriteError {
        source: KeyWriteErrorSource,
        key: SecretKey,
    },

    #[snafu(transparent)]
    KeyReadError { source: KeyReadErrorSource },
}

pub fn reading_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> PersistError {
    |e| PersistError::KeyReadError {
        source: KeyReadErrorSource::ReadFileError { source: e, file },
    }
}

pub fn writing_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> KeyWriteErrorSource {
    |e| KeyWriteErrorSource::WriteFileError { source: e, file }
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyReadErrorSource {
    #[snafu(transparent)]
    IOError {
        source: std::io::Error,
    },

    ReadFileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[snafu(transparent)]
    SshParsingError {
        source: ssh_key::Error,
    },

    #[snafu(transparent)]
    IrohParsingError {
        source: iroh::KeyParsingError,
    },

    InvalidKeyTypeError {
        algorithm: Option<String>,
    },
}

impl From<KeyParsingError> for PersistError {
    fn from(source: KeyParsingError) -> Self {
        PersistError::KeyReadError {
            source: KeyReadErrorSource::IrohParsingError { source },
        }
    }
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyWriteErrorSource {
    #[snafu(transparent)]
    IOError { source: std::io::Error },

    WriteFileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[snafu(transparent)]
    KeyEncodeError { source: ssh_key::Error },
}
