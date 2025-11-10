///! Error structs for iroh-persist
use std::path::PathBuf;

use iroh::SecretKey;
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

#[stack_error(derive, add_meta, std_sources)]
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
