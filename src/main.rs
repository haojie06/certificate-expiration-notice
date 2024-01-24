use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::RootCertStore;

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Allow using SSLKEYLOGFILE.
    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();
    let mut tls_stream = rustls::Stream::new(&mut conn, &mut sock);
    tls_stream
        .write_all(
            concat!(
                "GET / HTTP/1.1\r\n",
                "Host: www.rust-lang.org\r\n",
                "Connection: close\r\n",
                "Accept-Encoding: identity\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let cert = tls_stream.conn.peer_certificates().unwrap().last().unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert).unwrap();
    println!("Cert subject {}", cert.subject());
    println!("Cert issuer {}", cert.issuer());
    println!(
        "Cert Validity {} - {}",
        cert.validity().not_before,
        cert.validity().not_after
    );
    // for c in cert {}
    // let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    // writeln!(
    //     &mut std::io::stderr(),
    //     "Current ciphersuite: {:?}",
    //     ciphersuite.suite()
    // )
    // .unwrap();
    // let mut plaintext = Vec::new();
    // tls.read_to_end(&mut plaintext).unwrap();
    // stdout().write_all(&plaintext).unwrap();
}
