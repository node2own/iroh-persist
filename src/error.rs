///! Error structs for iroh-persist
use std::path::PathBuf;

use iroh::KeyParsingError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PersistError {
    #[snafu(transparent)]
    IOError { source: std::io::Error },

    FileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[snafu(transparent)]
    KeyEncodeError { source: ssh_key::Error },

    #[snafu(transparent)]
    KeyDecodeError { source: KeyDecodeErrorSource },
}

pub fn for_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> PersistError {
    return |e| PersistError::FileError { source: e, file };
}

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyDecodeErrorSource {
    #[snafu(transparent)]
    SshParsing {
        source: ssh_key::Error,
    },

    #[snafu(transparent)]
    IrohParsing {
        source: iroh::KeyParsingError,
    },

    InvalidKeyType {
        algorithm: Option<String>,
    },
}

impl PersistError {
    pub fn ssh_parsing_error(source: ssh_key::Error) -> Self {
        PersistError::KeyDecodeError {
            source: KeyDecodeErrorSource::SshParsing { source },
        }
    }
    pub fn ssh_serializing_error(source: ssh_key::Error) -> Self {
        PersistError::KeyEncodeError { source }
    }
}

impl From<KeyParsingError> for PersistError {
    fn from(source: KeyParsingError) -> Self {
        PersistError::KeyDecodeError {
            source: KeyDecodeErrorSource::IrohParsing { source },
        }
    }
}
