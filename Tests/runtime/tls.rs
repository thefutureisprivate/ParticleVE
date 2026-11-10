//! Actual loopback TLS verification with ephemeral certificates and no global CA writes.
use super::tls_config_from_pem;
use crate::common::{Error, Result, command, require};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct Certificates {
    _directory: tempfile::TempDir,
    ca: Vec<u8>,
    unknown_ca: Vec<u8>,
    certificate: Vec<u8>,
    expired: Vec<u8>,
    key: Vec<u8>,
    key_pem: Vec<u8>,
}
fn openssl(directory: &Path, arguments: &[&str]) -> Result<()> {
    let args = std::iter::once("/usr/bin/openssl".to_owned())
        .chain(arguments.iter().map(|s| (*s).to_owned()))
        .collect::<Vec<_>>();
    // All names are explicit temporary paths; no default OpenSSL configuration or trust file is modified.
    let result = command(&args, None, Some(Duration::from_secs(30)), 65536, false)?;
    require(
        result.code == 0,
        format!(
            "ephemeral TLS fixture failed in {}: {}",
            directory.display(),
            result.stderr
        ),
    )
}
impl Certificates {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let name = |file: &str| directory.path().join(file).display().to_string();
        for prefix in ["ca", "unknown-ca"] {
            openssl(
                directory.path(),
                &[
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-noenc",
                    "-keyout",
                    &name(&format!("{prefix}-key.pem")),
                    "-out",
                    &name(&format!("{prefix}.pem")),
                    "-subj",
                    &format!("/CN=ParticleVE disposable {prefix}"),
                    "-days",
                    "2",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                ],
            )?;
        }
        openssl(
            directory.path(),
            &[
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-noenc",
                "-keyout",
                &name("leaf-key.pem"),
                "-out",
                &name("leaf.csr"),
                "-subj",
                "/CN=localhost",
            ],
        )?;
        fs::write(directory.path().join("leaf.ext"),b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")?;
        openssl(
            directory.path(),
            &[
                "x509",
                "-req",
                "-in",
                &name("leaf.csr"),
                "-CA",
                &name("ca.pem"),
                "-CAkey",
                &name("ca-key.pem"),
                "-CAcreateserial",
                "-outform",
                "DER",
                "-out",
                &name("leaf.der"),
                "-days",
                "2",
                "-sha256",
                "-extfile",
                &name("leaf.ext"),
            ],
        )?;
        // Use explicit past dates, rather than a negative validity duration,
        // which modern OpenSSL correctly rejects as an invalid interval.
        fs::create_dir(directory.path().join("issued"))?;
        fs::write(directory.path().join("index.txt"), b"")?;
        fs::write(directory.path().join("serial"), b"01\n")?;
        fs::write(
            directory.path().join("ca.cnf"),
            format!(
                "[ca]\ndefault_ca=test\n[test]\ndatabase={}\nnew_certs_dir={}\nserial={}\nprivate_key={}\ncertificate={}\ndefault_md=sha256\ndefault_days=2\npolicy=policy\nx509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
                name("index.txt"),
                name("issued"),
                name("serial"),
                name("ca-key.pem"),
                name("ca.pem")
            ),
        )?;
        openssl(
            directory.path(),
            &[
                "ca",
                "-batch",
                "-notext",
                "-config",
                &name("ca.cnf"),
                "-startdate",
                "20200101000000Z",
                "-enddate",
                "20210101000000Z",
                "-in",
                &name("leaf.csr"),
                "-out",
                &name("expired.pem"),
            ],
        )?;
        openssl(
            directory.path(),
            &[
                "x509",
                "-in",
                &name("expired.pem"),
                "-outform",
                "DER",
                "-out",
                &name("expired.der"),
            ],
        )?;
        openssl(
            directory.path(),
            &[
                "pkcs8",
                "-in",
                &name("leaf-key.pem"),
                "-topk8",
                "-nocrypt",
                "-outform",
                "DER",
                "-out",
                &name("leaf-key.der"),
            ],
        )?;
        let ca = fs::read(directory.path().join("ca.pem"))?;
        let unknown_ca = fs::read(directory.path().join("unknown-ca.pem"))?;
        let certificate = fs::read(directory.path().join("leaf.der"))?;
        let expired = fs::read(directory.path().join("expired.der"))?;
        let key = fs::read(directory.path().join("leaf-key.der"))?;
        let key_pem = fs::read(directory.path().join("leaf-key.pem"))?;
        Ok(Self {
            _directory: directory,
            ca,
            unknown_ca,
            certificate,
            expired,
            key,
            key_pem,
        })
    }
}
fn server(certificate: &[u8], key: &[u8]) -> Result<(SocketAddr, thread::JoinHandle<Result<()>>)> {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::new(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(
            certificate.to_vec(),
        )],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key.to_vec(),
        )),
    )
    .map_err(|e| Error::new(e.to_string()))?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let handle = thread::spawn(move || -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    require(Instant::now() < deadline, "TLS test client did not connect")?;
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e.into()),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let connection = rustls::ServerConnection::new(Arc::new(config))
            .map_err(|e| Error::new(e.to_string()))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        while !request.windows(4).any(|s| s == b"\r\n\r\n") {
            let mut buffer = [0u8; 1024];
            let count = stream.read(&mut buffer)?;
            require(
                count > 0,
                "TLS test client closed before an authenticated request",
            )?;
            request.extend_from_slice(&buffer[..count]);
            require(request.len() <= 16384, "TLS test request exceeds its bound")?;
        }
        require(
            request.starts_with(b"GET /probe HTTP/1.1\r\n"),
            "unexpected TLS test request",
        )?;
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")?;
        stream.flush()?;
        Ok(())
    });
    Ok((address, handle))
}
fn exchange(
    certificates: &Certificates,
    certificate: &[u8],
    roots: &[u8],
    host: &str,
) -> Result<(Result<Vec<u8>>, Result<()>)> {
    let config = tls_config_from_pem(roots)?;
    let (address, handle) = server(certificate, &certificates.key)?;
    let outcome = (|| -> Result<Vec<u8>> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(3)))
            .tls_config(config)
            .build()
            .into();
        let mut response = agent
            .get(format!("https://{host}:{}/probe", address.port()))
            .call()
            .map_err(|e| Error::new(e.to_string()))?;
        require(response.status() == 200, "TLS test response status differs")?;
        let mut body = Vec::new();
        response
            .body_mut()
            .as_reader()
            .take(3)
            .read_to_end(&mut body)?;
        Ok(body)
    })();
    let served = handle
        .join()
        .map_err(|_| Error::new("TLS fixture thread panicked"))?;
    Ok((outcome, served))
}
#[test]
fn authenticates_loopback_and_rejects_unknown_ca_wrong_name_and_expiry() -> Result<()> {
    let certificates = Certificates::new()?;
    let (response, served) = exchange(
        &certificates,
        &certificates.certificate,
        &certificates.ca,
        "localhost",
    )?;
    assert_eq!(response?, b"ok");
    served?;
    let (response, _) = exchange(
        &certificates,
        &certificates.certificate,
        &certificates.unknown_ca,
        "localhost",
    )?;
    assert!(response.is_err(), "untrusted CA reached the HTTP server");
    let (response, _) = exchange(
        &certificates,
        &certificates.certificate,
        &certificates.ca,
        "127.0.0.1",
    )?;
    assert!(
        response.is_err(),
        "wrong certificate name reached the HTTP server"
    );
    let (response, _) = exchange(
        &certificates,
        &certificates.expired,
        &certificates.ca,
        "localhost",
    )?;
    assert!(
        response.is_err(),
        "expired certificate reached the HTTP server"
    );
    Ok(())
}
#[test]
fn system_store_parser_rejects_empty_corrupt_and_private_key_material() -> Result<()> {
    assert!(tls_config_from_pem(b"").is_err());
    assert!(
        tls_config_from_pem(b"-----BEGIN CERTIFICATE-----\nZW1wdHk=\n-----END CERTIFICATE-----\n")
            .is_err()
    );
    let certificates = Certificates::new()?;
    let mut contaminated = certificates.ca;
    contaminated.extend_from_slice(&certificates.key_pem);
    assert!(tls_config_from_pem(&contaminated).is_err());
    Ok(())
}
#[test]
fn https_only_policy_refuses_plaintext_before_connecting() -> Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(1)))
        .build()
        .into();
    assert!(agent.get(format!("http://{address}/probe")).call().is_err());
    assert!(
        listener
            .accept()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn reads_the_actual_fedora_extracted_public_store() -> Result<()> {
    super::tls_config()?;
    Ok(())
}
