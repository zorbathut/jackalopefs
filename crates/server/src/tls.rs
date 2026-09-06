//! Server certificate: loaded from the state directory, or generated once and persisted so its fingerprint stays stable across restarts.

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for Identity {
    fn clone(&self) -> Identity {
        Identity {
            cert: self.cert.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl Identity {
    /// Fresh self-signed certificate; not persisted.
    pub fn generate() -> anyhow::Result<Identity> {
        let generated = rcgen::generate_simple_self_signed(vec!["jackalopefs".to_string()])
            .context("generating certificate")?;
        Ok(Identity {
            cert: generated.cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                generated.signing_key.serialize_der(),
            )),
        })
    }

    /// Load `cert.der`/`key.der` from `state_dir`, generating and saving them if absent.
    pub fn load_or_generate(state_dir: &Path) -> anyhow::Result<Identity> {
        let cert_path = state_dir.join("cert.der");
        let key_path = state_dir.join("key.der");
        if cert_path.exists() && key_path.exists() {
            let cert =
                fs::read(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
            let key =
                fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
            return Ok(Identity {
                cert: CertificateDer::from(cert),
                key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
            });
        }
        let identity = Identity::generate()?;
        // Explicit modes throughout: the server runs with a zero umask, so nothing here may rely on it.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        let mut key_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .with_context(|| format!("creating {}", key_path.display()))?;
        std::io::Write::write_all(&mut key_file, identity.key.secret_der())
            .context("writing key")?;
        let mut cert_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&cert_path)
            .with_context(|| format!("creating {}", cert_path.display()))?;
        std::io::Write::write_all(&mut cert_file, identity.cert.as_ref())
            .context("writing certificate")?;
        tracing::info!("generated new certificate in {}", state_dir.display());
        Ok(identity)
    }

    pub fn fingerprint(&self) -> String {
        jackalopefs_proto::fingerprint(self.cert.as_ref())
    }
}

/// QUIC server configuration: TLS 1.3 with our certificate, the jackalopefs ALPN, and the given transport parameters.
pub fn server_config(
    identity: Identity,
    transport: Arc<quinn::TransportConfig>,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("TLS versions")?
    .with_no_client_auth()
    .with_single_cert(vec![identity.cert], identity.key)
    .context("certificate/key mismatch")?;
    tls.alpn_protocols = vec![jackalopefs_proto::ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("QUIC crypto config")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_across_loads() {
        // The server binary runs with a zero umask; the modes below must hold regardless.
        nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        let dir = tempfile::tempdir().unwrap();
        let first = Identity::load_or_generate(&dir.path().join("state")).unwrap();
        let second = Identity::load_or_generate(&dir.path().join("state")).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_ne!(
            first.fingerprint(),
            Identity::generate().unwrap().fingerprint()
        );
        let mode = |name: &str| {
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(dir.path().join("state").join(name))
                    .unwrap()
                    .permissions(),
            ) & 0o777
        };
        assert_eq!(mode("key.der"), 0o600);
        assert_eq!(mode("cert.der"), 0o644);
        assert_eq!(mode(""), 0o700);
    }
}
