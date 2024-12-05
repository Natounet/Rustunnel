use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use std::io::{Error as IoError, ErrorKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Resolves a domain name to its IP address
///
/// # Arguments
///
/// * `domain` - The domain name to resolve
///
/// # Returns
///
/// The resolved IP address or a SOCKS5 error
///
/// # Errors
///
/// Returns `Socks5Error::DomainLookupFailed` if resolution fails
async fn resolve_domain_to_ip(domain: &str) -> Result<String, String> {
    // Créer le resolver directement de manière asynchrone
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    // Utiliser le resolver
    let response = match resolver.lookup_ip(domain).await {
        Ok(result) => result,
        Err(e) => return Err(e.to_string()),
    };
    let addr = response
        .iter()
        .next()
        .ok_or(format!("Resolution for the domain {} failed", domain))?;

    Ok(addr.to_string())
}

/// Establishes a TCP connection to a target service
///
/// # Arguments
///
/// * `ip` - The target IP address
/// * `port` - The target service port
///
/// # Returns
///
/// A connected TCP socket or an I/O error
async fn connect_to_service(ip: &str, port: u16) -> Result<TcpStream, IoError> {
    // Construct full address string
    let address = format!("{}:{}", ip, port);

    // Attempt to connect to the service
    let socket = TcpStream::connect(address).await?;
    println!("Connected to {}:{}", ip, port);
    Ok(socket)
}

/// Bidirectional proxy handler that logs TCP traffic between a client and a service
///
/// # Arguments
///
/// * `client_socket` - The TCP stream connected to the client
/// * `service_socket` - The TCP stream connected to the target service
///
/// # Returns
///
/// Returns `io::Result<()>` which is:
/// * `Ok(())` if the proxy operation completed successfully
/// * `Err(e)` if an I/O error occurred during the operation
///
/// # Example
///
/// ```no_run
/// use tokio::net::TcpStream;
///
/// async fn example() -> std::io::Result<()> {
///     let client_stream = TcpStream::connect("127.0.0.1:1234").await?;
///     let service_stream = TcpStream::connect("example.com:80").await?;
///
///     proxy_bidirectional(client_stream, service_stream).await?;
///     Ok(())
/// }
/// ```
///
/// # Notes
///
/// * Uses 8KB buffers for each direction
/// * Logs traffic in both directions with hex and ASCII representation
/// * Automatically terminates when either connection is closed
async fn proxy_bidirectional(
    mut client_socket: &mut TcpStream,
    mut service_socket: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client_read, mut client_write) = client_socket.split();
    let (mut service_read, mut service_write) = service_socket.split();

    // Tampon pour stocker temporairement les données
    let mut buffer_client = [0u8; 8192];
    let mut buffer_service = [0u8; 8192];

    loop {
        tokio::select! {
            // Client -> Service
            result = client_read.read(&mut buffer_client) => {
                match result? {
                    0 => {
                        println!("[INFO] The client closed the connection.");
                        break;
                    }
                    n => {
                        // Log des données du client vers le service
                        println!("Client -> Service: {} bytes", n);
                        //println!("Data: {:?}", &buffer_client[..n]);

                        // Envoie au service
                        service_write.write_all(&buffer_client[..n]).await?;
                    }
                }
            }
            // Service -> Client
            result = service_read.read(&mut buffer_service) => {
                match result? {
                    0 => {
                        println!("[INFO] The server closed the connection");
                        break;
                    }
                    n => {
                        // Log des données du service vers le client
                        println!("Service -> Client: {} bytes", n);
                        //println!("Data: {:?}", &buffer_service[..n]);

                        // Envoie au client
                        client_write.write_all(&buffer_service[..n]).await?;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Handles the initial SOCKS5 handshake (method selection)
///
/// # Arguments
///
/// * `socket` - The client's TCP connection
///
/// # Returns
///
/// Success or a specific SOCKS5 error
///
/// # Errors
///
/// Possible errors include invalid format or no acceptable methods
async fn handle_socks5_handshake(socket: &mut TcpStream) -> Result<(), String> {
    let mut buf = [0; 1024];

    // Read client's method selection message
    let n = match socket.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => return Err(e.to_string()),
    };

    // Validate SOCKS5 version
    if n < 2 || buf[0] != 0x05 {
        return Err("ERROR : Invalid SOCKS5 format".to_string());
    }

    // Check number of authentication methods
    let auth_count = buf[1] as usize;
    if n < 2 + auth_count {
        return Err("ERROR : Invalid SOCKS5 request format".to_string());
    }

    // Check for no authentication method (0x00)
    let auth_methods = &buf[2..2 + auth_count];
    if !auth_methods.contains(&0x00) {
        // Respond with "No acceptable methods"
        match socket.write_all(&[0x05, 0xFF]).await {
            Ok(_) => (),
            Err(e) => return Err(e.to_string()),
        };
        return Err("ERROR : No acceptable methods".to_string());
    }

    // Respond with successful no-authentication method
    match socket.write_all(&[0x05, 0x00]).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Handles the client's TCP connection request
///
/// # Arguments
///
/// * `socket` - The client's TCP connection
///
/// # Returns
///
/// Success or an I/O error
///
/// # Errors
///
/// Possible errors include invalid request, domain resolution failure, etc.
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
    if let Err(e) = proxy_bidirectional(socket, service_socket).await {
        return Err(IoError::new(ErrorKind::Other, e.to_string()));
    }

    Ok(())
}

/// Handles an individual client connection
///
/// # Arguments
///
/// * `socket` - The client's TCP connection
///
/// Performs SOCKS5 handshake and connection request processing
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

/// Main entry point for the SOCKS5 proxy server
///
/// # Configuration
///
/// - Listens on localhost:1080
/// - Uses 10 worker threads
/// - Handles connections concurrently
///
/// # Panics
///
/// May panic if port binding fails
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
