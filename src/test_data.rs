use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// The embedded certificate chain bytes for testing.
pub const TEST_CERT_PEM: &[u8] = include_bytes!("../testdata/server.cert");

/// The embedded private key bytes for testing.
pub const TEST_KEY_PEM: &[u8] = include_bytes!("../testdata/server.key");

#[allow(unused)]
pub fn load_certs_and_key()
-> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>> {
    // 1. Load Certificate Chain
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(TEST_CERT_PEM)
        .filter_map(|result| result.ok())
        .collect();

    if certs.is_empty() {
        return Err("No certificates found in PEM slice".into());
    }

    // 2. Load Private Key
    // We iterate over the PrivateKeyDer iterator and take the first one.
    // The `pem_slice_iter` handles both PKCS#8 and other formats.
    let key_der: Option<PrivateKeyDer<'static>> = PrivateKeyDer::pem_slice_iter(TEST_KEY_PEM)
        .filter_map(|result| result.ok())
        .next();

    let key = key_der.ok_or("No private key found in PEM slice")?;

    // Since we're using embedded bytes, we can safely return the 'static lifetime.
    Ok((certs, key))
}
