use std::path::{Path, PathBuf};

use iroh::SecretKey;
use n0_snafu::{Result, format_err};
use ssh_key::Algorithm;
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
};
use tracing::log::{debug, error};

pub async fn get_secret_key(persist_at: Option<PathBuf>) -> SecretKey {
    get_secret_key_from_ref(persist_at.as_ref()).await
}

pub async fn get_secret_key_from_ref(mut persist_at: Option<&PathBuf>) -> SecretKey {
    match read_key(persist_at).await {
        Ok(Some(result)) => return result,
        Ok(None) => (),
        Err(error) => {
            error!("Error reading persisted {persist_at:?} key: [{error:?}]");
            persist_at = None; // Don't overwrite the key that we couln't read
        }
    };

    let key = SecretKey::generate(&mut rand::rng());
    debug!("Generate new key: {key:?}");
    if let Some(node_path) = persist_at {
        if let Err(error) = write_key(&node_path, &key).await {
            error!("Could not persist {persist_at:?} key: {node_path:?}: {error:?}");
        }
    }
    key
}

pub fn default_persist_at<S: AsRef<str>>(app_name: S) -> Option<PathBuf> {
    dirs::config_dir().map(|mut p| {
        p.push(app_name.as_ref());
        p.push("iroh-secret-key.pem");
        debug!("Persisting key at: {p:?}");
        p
    })
}

async fn read_key(key_path_option: Option<&PathBuf>) -> Result<Option<SecretKey>> {
    if let Some(key_path) = key_path_option {
        if !key_path.exists() {
            debug!("Secret key not found: {:?}", &key_path);
            return Ok(None);
        }
        let keystr = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| format_err!("Read key error: {key_path:?}: {e:?}"))?;
        let ser_key = ssh_key::private::PrivateKey::from_openssh(keystr)
            .map_err(|e| format_err!("Parse key error: {key_path:?}: {e:?}"))?;
        let ssh_key::private::KeypairData::Ed25519(kp) = ser_key.key_data() else {
            let algorithm = ser_key.key_data().algorithm().ok();
            let algorithm_name = algorithm
                .as_ref()
                .map(Algorithm::as_str)
                .map(ToString::to_string);
            return Err(format_err!(
                "Invalid key type: {key_path:?}: {algorithm_name:?}"
            ));
        };
        let key = SecretKey::from_bytes(&kp.private.to_bytes());
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

async fn write_key(key_path: &Path, secret_key: &SecretKey) -> Result<()> {
    let ckey = ssh_key::private::Ed25519Keypair {
        public: secret_key.public().as_verifying_key().into(),
        private: secret_key.as_signing_key().into(),
    };
    let ser_key = ssh_key::private::PrivateKey::from(ckey)
        .to_openssh(ssh_key::LineEnding::default())
        .map_err(|e| format_err!("Error serializing SSH key: {e:?}"))?;

    create_secret_file(key_path, ser_key.as_str()).await?;
    Ok(())
}

async fn create_secret_file(file: &Path, content: &str) -> Result {
    let mut parent = file.to_owned();
    if parent.pop() {
        fs::create_dir_all(parent.clone())
            .await
            .map_err(|e| format_err!("Error creating directory {parent:?}: {e:?}"))?
    }

    let mut open_options = OpenOptions::new();

    #[cfg(unix)]
    open_options.mode(0o400); // Read for owner only

    let mut open_file = (open_options.create(true).write(true).open(file))
        .await
        .map_err(|e| format_err!("Error creating secret-file: {file:?}: {e:?}"))?;
    open_file
        .write_all(content.as_bytes())
        .await
        .map_err(|e| format_err!("Error writing secret-file: {file:?}: {e:?}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_generates_emphemeral_keys() {
        let first_key = get_secret_key_from_ref(None).await;
        let second_key = get_secret_key_from_ref(None).await;
        assert_ne!(first_key.to_bytes(), second_key.to_bytes());
    }

    #[tokio::test]
    async fn it_stores_different_keys() {
        let first_key = get_secret_key(Some("target/test/iroh-secret-foo.pem".into())).await;
        let second_key = get_secret_key(Some("target/test/iroh-secret-bar.pem".into())).await;
        assert_ne!(first_key.to_bytes(), second_key.to_bytes());
    }

    #[tokio::test]
    async fn it_reuses_a_key_from_a_given_location() {
        let first_key = get_secret_key(Some("target/test/iroh-secret-foo.pem".into())).await;
        let second_key = get_secret_key(
            Some("target/test/iroh-secret-foo.pem".into()).or_else(|| default_persist_at("bar")),
        )
        .await;
        let third_key = get_secret_key(Some("target/test/iroh-secret-bar.pem".into())).await;
        assert_eq!(first_key.to_bytes(), second_key.to_bytes());
        assert_ne!(first_key.to_bytes(), third_key.to_bytes());
    }

    #[tokio::test]
    async fn it_reuses_a_key_from_a_default_location() {
        let first_key = get_secret_key(default_persist_at("foo")).await;
        let persist_at_foo = None::<PathBuf>.or_else(|| default_persist_at("foo"));
        let second_key = get_secret_key_from_ref(persist_at_foo.as_ref()).await;
        let third_key = get_secret_key(Some("target/test/iroh-secret-bar.pem".into())).await;
        assert_eq!(first_key.to_bytes(), second_key.to_bytes());
        assert_ne!(first_key.to_bytes(), third_key.to_bytes());
    }

    // TODO: add more tests
}
