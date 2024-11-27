use std::io::{Error as IoError, ErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use trust_dns_resolver::config::*;
use trust_dns_resolver::AsyncResolver;

// Implémentation d'un serveur Proxy de base
// Prochaines étapes :
// - Implémenter la logique de fragmentation
// - Implémenter l'envoie des requêtes DNS

// Custom error enum for SOCKS5 specific errors
#[derive(Debug)]
enum Socks5Error {
    InvalidFormat,       // Invalid request format
    NoAcceptableMethods, // No supported authentication method
    IoError(IoError),    // I/O related errors
    DomainLookupFailed,  // DNS resolution failed
}

// Convert IoError to Socks5Error for error handling
impl From<IoError> for Socks5Error {
    fn from(e: IoError) -> Self {
        Socks5Error::IoError(e)
    }
}

// Resolve domain name to IP address
async fn resolve_domain_to_ip(domain: &str) -> Result<String, Socks5Error> {
    // Create DNS resolver with default configuration
    let resolver = AsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        .map_err(|_| Socks5Error::DomainLookupFailed)?;

    // Perform DNS lookup for the domain
    let response = resolver
        .lookup_ip(domain)
        .await
        .map_err(|_| Socks5Error::DomainLookupFailed)?;

    // Return the first resolved IP address
    response
        .iter()
        .next()
        .map(|ip| ip.to_string())
        .ok_or_else(|| {
            eprintln!("[ERROR] No IP addresses found for domain: {}", domain);
            Socks5Error::DomainLookupFailed
        })
}

// Establish TCP connection to target service
async fn connect_to_service(ip: &str, port: u16) -> Result<TcpStream, IoError> {
    // Construct full address string
    let address = format!("{}:{}", ip, port);
    // Attempt to connect to the service
    let socket = TcpStream::connect(address).await?;
    Ok(socket)
}

// Handle SOCKS5 initial handshake (method selection)
async fn handle_socks5_handshake(socket: &mut TcpStream) -> Result<(), Socks5Error> {
    let mut buf = [0; 1024];
    // Read client's method selection message
    let n = socket.read(&mut buf).await?;

    // Validate SOCKS5 version
    if n < 2 || buf[0] != 0x05 {
        return Err(Socks5Error::InvalidFormat);
    }

    // Check number of authentication methods
    let auth_count = buf[1] as usize;
    if n < 2 + auth_count {
        return Err(Socks5Error::InvalidFormat);
    }

    // Check for no authentication method (0x00)
    let auth_methods = &buf[2..2 + auth_count];
    if !auth_methods.contains(&0x00) {
        // Respond with "No acceptable methods"
        socket.write_all(&[0x05, 0xFF]).await?;
        return Err(Socks5Error::NoAcceptableMethods);
    }

    // Respond with successful no-authentication method
    socket.write_all(&[0x05, 0x00]).await?;
    Ok(())
}

// Handle client's connection request
async fn handle_client_tcp_connect(socket: &mut TcpStream) -> Result<(), IoError> {
    let mut buf = [0; 1024];
    // Read connection request
    let n = socket.read(&mut buf).await?;
    if n < 4 {
        return Err(IoError::new(ErrorKind::InvalidData, "Request too short"));
    }

    // Validate SOCKS5 request format
    if buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Invalid SOCKS5 request",
        ));
    }

    // Parse destination address based on address type
    let addr_type = buf[3];
    let (dst_addr, total_len) = match addr_type {
        0x01 => {
            // IPv4 address
            if n < 10 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Incomplete IPv4 request",
                ));
            }
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            (ip, 8)
        }
        0x03 => {
            // Domain name
            let domain_len = buf[4] as usize;
            if n < domain_len + 7 {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Incomplete domain request",
                ));
            }
            let domain = match String::from_utf8(buf[5..5 + domain_len].to_vec()) {
                Ok(d) => d,
                Err(_) => return Err(IoError::new(ErrorKind::InvalidData, "Invalid domain")),
            };
            (domain, domain_len + 5)
        }
        0x04 => return Err(IoError::new(ErrorKind::InvalidInput, "IPv6 not supported")),
        _ => {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "Unsupported address type",
            ))
        }
    };

    // Extract destination port
    let dst_port = u16::from_be_bytes([buf[total_len], buf[total_len + 1]]);

    // Resolve domain to IP if needed
    let target_ip = if addr_type == 0x03 {
        match resolve_domain_to_ip(&dst_addr).await {
            Ok(ip) => ip,
            Err(_) => return Err(IoError::new(ErrorKind::Other, "Domain resolution failed")),
        }
    } else {
        dst_addr
    };

    // Establish connection to target service
    let mut service_socket = match connect_to_service(&target_ip, dst_port).await {
        Ok(socket) => socket,
        Err(_) => {
            return Err(IoError::new(
                ErrorKind::ConnectionRefused,
                "Service connection failed",
            ))
        }
    };

    // Send successful connection response
    socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // Proxy data between client and target service
    tokio::io::copy_bidirectional(socket, &mut service_socket).await?;

    Ok(())
}

// Handle individual client connection
async fn handle_connection(mut socket: TcpStream) {
    // Perform SOCKS5 handshake
    if let Err(e) = handle_socks5_handshake(&mut socket).await {
        eprintln!("[ERROR] SOCKS5 handshake failed: {:?}", e);
        return;
    }

    // Handle TCP connection request
    if let Err(e) = handle_client_tcp_connect(&mut socket).await {
        eprintln!("[ERROR] TCP connection error: {:?}", e);
    }
}

// Main entry point - SOCKS5 proxy server
#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    // Bind to localhost on port 1080 (standard SOCKS5 port)
    let listener = TcpListener::bind("127.0.0.1:1080")
        .await
        .expect("[ERROR] Failed to bind to address");

    println!("[INFO] Listening on 127.0.0.1:1080");

    // Accept and handle incoming connections concurrently
    while let Ok((socket, addr)) = listener.accept().await {
        println!("[INFO] Accepted connection from {:?}", addr);
        tokio::spawn(handle_connection(socket));
    }
}
