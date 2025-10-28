use std::{
    borrow::Cow,
    fmt::Debug,
    path::{Path, PathBuf},
    str::FromStr,
};

use iroh::{KeyParsingError, SecretKey};
use n0_snafu::Result;
use ssh_key::Algorithm;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::{debug, error, info, warn};

pub mod error;

pub use crate::error::*;

pub async fn get_secret_key_magic(
    persist: bool,
    app_name: Cow<'_, str>,
    persist_at: Option<&PathBuf>,
) -> SecretKey {
    if persist || persist_at.is_some() {
        let persist_location = persist_at
            .map(PathBuf::to_owned)
            .or_else(|| default_persist_at(app_name));
        return get_secret_key_from_option(persist_location).await;
    }
    if let Some(secret_key) = try_get_secret_key_from_env().ok().flatten() {
        info!("Using ephemeral secret key from environment");
        return secret_key;
    }
    generate_key()
}

pub fn try_get_secret_key_from_env() -> Result<Option<SecretKey>, PersistError> {
    if let Ok(hex_secret) = std::env::var("IROH_SECRET") {
        return iroh::SecretKey::from_str(&hex_secret)
            .map(Option::Some)
            .map_err(KeyParsingError::into);
    }
    Ok(None)
}

pub async fn get_secret_key(persist_at: PathBuf) -> SecretKey {
    get_secret_key_from_ref(&persist_at).await
}

pub async fn get_secret_key_from_ref(persist_at: &PathBuf) -> SecretKey {
    match try_get_secret_key_from_ref(persist_at).await {
        Ok(secret_key) => secret_key,
        Err(error) => handle_error(error, persist_at),
    }
}

pub async fn get_secret_key_from_option(persist_at: Option<PathBuf>) -> SecretKey {
    get_secret_key_from_option_ref(persist_at.as_ref()).await
}

pub async fn get_secret_key_from_option_ref(persist_at: Option<&PathBuf>) -> SecretKey {
    match try_get_secret_key_from_option_ref(persist_at).await {
        Ok(secret_key) => secret_key,
        Err(error) => handle_error(error, &persist_at),
    }
}

fn handle_error<P: Debug>(error: PersistError, persist_at: &P) -> SecretKey {
    let secret_key = match error {
        PersistError::KeyReadError { source } => {
            error!("Error reading persisted {persist_at:?} key: [{source:?}]");
            generate_key()
        }
        PersistError::KeyWriteError { source, key } => {
            error!("Error writing persisted {persist_at:?} key: [{source:?}]");
            key
        }
    };
    warn!("Falling back to ephemeral key");
    secret_key
}

pub async fn try_get_secret_key_from_option(
    persist_at: Option<PathBuf>,
) -> Result<SecretKey, PersistError> {
    try_get_secret_key_from_option_ref(persist_at.as_ref()).await
}

pub async fn try_get_secret_key_from_option_ref(
    persist_at: Option<&PathBuf>,
) -> Result<SecretKey, PersistError> {
    if let Some(node_path) = persist_at {
        try_get_secret_key_from_ref(node_path).await
    } else {
        warn!("No key path; falling back to ephemeral key");
        Ok(generate_key())
    }
}

pub async fn try_get_secret_key(persist_at: PathBuf) -> Result<SecretKey, PersistError> {
    try_get_secret_key_from_ref(&persist_at).await
}

pub async fn try_get_secret_key_from_ref(persist_at: &PathBuf) -> Result<SecretKey, PersistError> {
    if let Some(result) = read_key(persist_at).await? {
        info!("Using secret key {persist_at:?}");
        return Ok(result);
    };
    if let Some(result) = try_get_secret_key_from_env()? {
        info!("Using secret key from environment");
        return Ok(result);
    }

    let key = generate_key();
    write_key(persist_at, &key).await?;
    Ok(key)
}

pub fn generate_key() -> SecretKey {
    let result = SecretKey::generate(&mut rand::rng());
    info!("Generated new key");
    result
}

pub fn default_persist_at<S: AsRef<str>>(app_name: S) -> Option<PathBuf> {
    dirs::config_dir().map(|mut p| {
        p.push(app_name.as_ref());
        p.push("iroh-secret-key.pem");
        debug!("Persisting key at: {p:?}");
        p
    })
}

async fn read_key(key_path: &PathBuf) -> Result<Option<SecretKey>, PersistError> {
    if !key_path.exists() {
        debug!("Secret key not found: {:?}", &key_path);
        return Ok(None);
    }
    let keystr = tokio::fs::read_to_string(key_path)
        .await
        .map_err(reading_file(key_path.clone()))?;
    let ser_key = ssh_key::private::PrivateKey::from_openssh(keystr)
        .map_err(KeyReadErrorSource::from)
        .map_err(PersistError::from)?;
    let ssh_key::private::KeypairData::Ed25519(kp) = ser_key.key_data() else {
        let key_algorithm = ser_key.key_data().algorithm().ok();
        let algorithm = key_algorithm
            .as_ref()
            .map(Algorithm::as_str)
            .map(ToString::to_string);
        return Err(KeyReadErrorSource::InvalidKeyTypeError { algorithm }.into());
    };
    let key = SecretKey::from_bytes(&kp.private.to_bytes());
    info!("Read key from {key_path:?}");
    Ok(Some(key))
}

async fn write_key(key_path: &Path, secret_key: &SecretKey) -> Result<(), PersistError> {
    let ckey = ssh_key::private::Ed25519Keypair {
        public: secret_key.public().as_verifying_key().into(),
        private: secret_key.as_signing_key().into(),
    };
    let ser_key = ssh_key::private::PrivateKey::from(ckey)
        .to_openssh(ssh_key::LineEnding::default())
        .map_err(KeyWriteErrorSource::from)
        .map_err(with_key(&secret_key))?;

    create_secret_file(key_path, ser_key.as_str())
        .await
        .map_err(with_key(secret_key))?;
    info!("Wrote key to {key_path:?}");
    Ok(())
}

fn with_key(key: &SecretKey) -> impl FnOnce(KeyWriteErrorSource) -> PersistError {
    |e| PersistError::KeyWriteError {
        source: e,
        key: key.to_owned(),
    }
}

async fn create_secret_file(file: &Path, content: &str) -> Result<(), KeyWriteErrorSource> {
    let mut parent = file.to_owned();
    if parent.pop() {
        fs::create_dir_all(parent.clone())
            .await
            .map_err(writing_file(parent))?
    }

    let mut open_options = OpenOptions::new();

    #[cfg(unix)]
    open_options.mode(0o400); // Read for owner only

    let mut open_file = (open_options.create(true).write(true).open(file))
        .await
        .map_err(writing_file(file.to_owned()))?;
    open_file
        .write_all(content.as_bytes())
        .await
        .map_err(writing_file(file.to_owned()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTmpDir {
        dir: PathBuf,
        dir_str: String,
    }

    impl TestTmpDir {
        async fn create() -> Self {
            let id: u32 = rand::random();
            let dir_str = format!("target/test-{id:x}");
            let dir: PathBuf = (&dir_str).into();
            tokio::fs::create_dir_all(&dir).await.unwrap();
            TestTmpDir { dir, dir_str }
        }
        fn dir_str(&self) -> &str {
            &self.dir_str
        }
    }

    impl Drop for TestTmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).unwrap();
        }
    }

    #[tokio::test]
    #[test_log::test]
    async fn it_generates_emphemeral_keys() {
        let first_key = get_secret_key_from_option(None).await;
        let second_key = get_secret_key_from_option(None).await;
        assert_ne!(first_key.to_bytes(), second_key.to_bytes());
    }

    #[tokio::test]
    #[test_log::test]
    async fn it_stores_different_keys() {
        let test_tmp_dir = TestTmpDir::create().await;
        let tmp_dir = test_tmp_dir.dir_str();
        let first_key = get_secret_key(format!("{tmp_dir}/iroh-secret-foo.pem").into()).await;
        let second_key = get_secret_key(format!("{tmp_dir}/test/iroh-secret-bar.pem").into()).await;
        assert_ne!(first_key.to_bytes(), second_key.to_bytes());
    }

    #[tokio::test]
    #[test_log::test]
    async fn it_reuses_a_key_from_a_given_location() {
        let test_tmp_dir = TestTmpDir::create().await;
        let tmp_dir = test_tmp_dir.dir_str();
        let first_key = get_secret_key(format!("{tmp_dir}/test/iroh-secret-foo.pem").into()).await;
        let second_location = Some(format!("{tmp_dir}/test/iroh-secret-foo.pem").into())
            .or_else(|| default_persist_at("bar"));
        debug!("Second location: {second_location:?}");
        let second_key = get_secret_key_from_option(second_location).await;
        let third_key = get_secret_key(format!("{tmp_dir}/test/iroh-secret-bar.pem").into()).await;
        assert_eq!(first_key.to_bytes(), second_key.to_bytes());
        assert_ne!(first_key.to_bytes(), third_key.to_bytes());
    }

    #[tokio::test]
    #[test_log::test]
    async fn it_reuses_a_key_from_a_default_location() {
        let test_tmp_dir = TestTmpDir::create().await;
        let tmp_dir = test_tmp_dir.dir_str();
        let first_key = get_secret_key_from_option(default_persist_at("foo")).await;
        let persist_at_foo = None::<PathBuf>.or_else(|| default_persist_at("foo"));
        let second_key = get_secret_key_from_option_ref(persist_at_foo.as_ref()).await;
        let third_key = get_secret_key(format!("{tmp_dir}/test/iroh-secret-bar.pem").into()).await;
        assert_eq!(first_key.to_bytes(), second_key.to_bytes());
        assert_ne!(first_key.to_bytes(), third_key.to_bytes());
    }

    #[tokio::test]
    #[test_log::test]
    async fn it_uses_an_ephemeral_key_when_it_cannot_read_key() {
        let test_tmp_dir = TestTmpDir::create().await;
        let tmp_dir = test_tmp_dir.dir_str();
        let file_path: PathBuf = format!("{tmp_dir}/iroh-secret-foo.pem").into();
        fs::write(&file_path, "nonsense".as_bytes().to_owned())
            .await
            .unwrap();
        let first_key = get_secret_key_from_ref(&file_path).await;
        let second_key = get_secret_key_from_ref(&file_path).await;
        assert_ne!(first_key.to_bytes(), second_key.to_bytes());
    }
}
