///! Error structs for iroh-persist
use std::path::PathBuf;

use iroh::{KeyParsingError, SecretKey};
use n0_error::{e, stack_error};

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum PersistError {
    KeyWriteError {
        source: KeyWriteErrorSource,
        key: SecretKey,
    },

    #[error(transparent)]
    KeyReadError { source: KeyReadErrorSource },
}

pub fn reading_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> PersistError {
    |e| {
        e!(PersistError::KeyReadError {
            source: e!(KeyReadErrorSource::ReadFileError { source: e, file }),
        })
    }
}

pub fn writing_file(file: PathBuf) -> impl FnOnce(std::io::Error) -> KeyWriteErrorSource {
    |e| e!(KeyWriteErrorSource::WriteFileError { source: e, file })
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum KeyReadErrorSource {
    #[error(transparent)]
    IOError {
        source: std::io::Error,
    },

    ReadFileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[error(transparent)]
    SshParsingError {
        #[error(std_err)]
        source: ssh_key::Error,
    },

    #[error(transparent)]
    IrohParsingError {
        source: iroh::KeyParsingError,
    },

    InvalidKeyTypeError {
        algorithm: Option<String>,
    },
}

impl From<KeyParsingError> for PersistError {
    fn from(source: KeyParsingError) -> Self {
        e!(PersistError::KeyReadError {
            source: e!(KeyReadErrorSource::IrohParsingError { source }),
        })
    }
}

impl From<ssh_key::Error> for KeyReadErrorSource {
    fn from(source: ssh_key::Error) -> Self {
        e!(KeyReadErrorSource::SshParsingError { source })
    }
}

impl From<KeyReadErrorSource> for PersistError {
    fn from(source: KeyReadErrorSource) -> Self {
        e!(PersistError::KeyReadError { source })
    }
}

#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum KeyWriteErrorSource {
    #[error(transparent)]
    IOError { source: std::io::Error },

    WriteFileError {
        source: std::io::Error,
        file: PathBuf,
    },

    #[error(transparent)]
    KeyEncodeError {
        #[error(std_err)]
        source: ssh_key::Error,
    },
}

impl From<ssh_key::Error> for KeyWriteErrorSource {
    fn from(source: ssh_key::Error) -> Self {
        e!(KeyWriteErrorSource::KeyEncodeError { source })
    }
}
