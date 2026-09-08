//! Encryption without authentication, for https teeUrls.
//!
//! Nodes built after 0g-tapp#110 register `https://host:50052` — a baked nginx
//! front with a self-signed certificate regenerated on every boot. There is
//! nothing to validate that certificate against, and nothing that needs to be:
//! evidence is Intel-signed and replay-checked, so the channel carries no trust
//! of its own. What must NOT happen is silently downgrading to plaintext, and
//! what must still be verified is the TLS *signature* (a peer that cannot sign
//! with the key in its own certificate is broken, not merely anonymous).
//!
//! tonic 0.12 cannot be handed a rustls config (that arrived in 0.13), so the
//! TLS is done in a connector, the same way 0g-tapp's pinned_tls does it.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

/// Accepts any server certificate; still verifies handshake signatures.
#[derive(Debug)]
struct AcceptAny {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
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
    ) -> Result<HandshakeSignatureValid, TlsError> {
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

/// A gRPC channel to an `https://` url whose certificate is accepted unseen.
pub async fn grpc_channel_any(url: &str) -> Result<tonic::transport::Channel> {
    use tokio_rustls::TlsConnector;
    use tonic::transport::Endpoint;

    let uri: http::Uri = url.parse().with_context(|| format!("bad endpoint {url}"))?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("{url}: no host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("tls config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
        .with_no_client_auth();
    // gRPC is HTTP/2; without ALPN the server may negotiate 1.1 or refuse.
    config.alpn_protocols = vec![b"h2".to_vec()];
    let config = Arc::new(config);

    // The connector below does the TLS; tonic must not layer its own on top, and
    // an https scheme would make it try — the scheme here only routes requests.
    let plain = url.replacen("https://", "http://", 1);
    Endpoint::from_shared(plain)
        .with_context(|| format!("endpoint {url}"))?
        .connect_with_connector(tower::service_fn(move |_| {
            let (host, config) = (host.clone(), config.clone());
            async move {
                let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                // Required by the API, ignored by the verifier: self-signed
                // certificates carry whatever name they gave themselves.
                let name = rustls::pki_types::ServerName::try_from(host.clone())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                let tls = TlsConnector::from(config).connect(name, tcp).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
        .await
        .with_context(|| format!("connect {url}"))
}

#[cfg(test)]
mod tests {
    /// Needs a live front at https://127.0.0.1:50052 proxying a tapp daemon.
    #[tokio::test]
    #[ignore]
    async fn probe_local_front() {
        let ch = super::grpc_channel_any("https://127.0.0.1:50052")
            .await
            .expect("tls connect");
        let mut c = crate::attest::tapp::tapp_service_client::TappServiceClient::new(ch);
        let r = c
            .get_evidence(tonic::Request::new(crate::attest::tapp::GetEvidenceRequest {
                app_id: "0g-attestor-dev".into(),
            }))
            .await
            .expect("rpc");
        println!("evidence: {} bytes", r.get_ref().evidence.len());
    }
}
