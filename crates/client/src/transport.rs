//! QUIC client configuration: TLS 1.3 with the server certificate either pinned by fingerprint or (explicitly) trusted blindly, plus the transport windows and liveness timers.

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::sync::Arc;
use subtle::ConstantTimeEq;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerTrust {
    /// Accept only a certificate with this SHA-256 fingerprint.
    Fingerprint([u8; 32]),
    /// Accept any certificate. The connection is still encrypted, but not authenticated.
    Insecure,
}

#[derive(Debug)]
struct VerifierPinned {
    trust: ServerTrust,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for VerifierPinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.trust {
            ServerTrust::Insecure => Ok(ServerCertVerified::assertion()),
            ServerTrust::Fingerprint(expected) => {
                let actual = jackalopefs_proto::fingerprint_bytes(end_entity.as_ref());
                if bool::from(actual.ct_eq(expected)) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!(
                        "server certificate fingerprint is {}, not the pinned one",
                        jackalopefs_proto::fingerprint(end_entity.as_ref())
                    )))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

const STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;
const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

pub fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            crate::IDLE_TIMEOUT
                .try_into()
                .expect("idle timeout fits a VarInt"),
        ))
        .keep_alive_interval(Some(crate::KEEP_ALIVE))
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(CONNECTION_WINDOW.into())
        .send_window(CONNECTION_WINDOW as u64)
        .max_concurrent_uni_streams(8u32.into());
    transport
}

pub fn client_config(trust: ServerTrust) -> anyhow::Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("TLS versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(VerifierPinned { trust, provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![jackalopefs_proto::ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("QUIC crypto config")?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()));
    Ok(config)
}
