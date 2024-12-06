use hickory_resolver::config::ResolverConfig;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::TokioAsyncResolver;
use rustunnel_lib::dns::*;
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
    println!("[INFO] Starting domain resolution for {}", domain);
    // Use a pre-configured global resolver or create it outside the async function
    let resolver = get_resolver(); // Assuming you have a get_resolver() function

    match resolver.lookup_ip(domain).await {
        Ok(response) => {
            let addr = response.iter().next().ok_or(format!(
                "[ERROR] Resolution for the domain {} failed",
                domain
            ))?;

            println!("[INFO] Successfully resolved {} to {}", domain, addr);
            Ok(addr.to_string())
        }
        Err(e) => {
            println!("[ERROR] Failed to resolve domain {}: {}", domain, e);
            Err(e.to_string())
        }
    }
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
async fn connect_to_service(ip: &str, port: u16) -> Result<u16, IoError> {
    println!("[INFO] Trying to connect to {}:{}", ip, port);
    // Construct full address string
    match create_tcp_session(&ip, port, "natounet.com", &get_resolver()).await {
        Ok(session_id) => {
            println!("[INFO] Successfully connected to {}:{}", ip, port);
            Ok(session_id)
        }
        Err(e) => {
            println!("[ERROR] Connection failed to {}:{} - {}", ip, port, e);
            return Err(std::io::Error::new(
                ErrorKind::ConnectionRefused,
                format!("Failed to connect to {}:{} - {}", ip, port, e),
            ));
        }
    }
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
    mut session_id: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "[INFO] Starting bidirectional proxy for session {}",
        session_id
    );
    let (mut client_read, mut client_write) = client_socket.split();

    // Tampon pour stocker temporairement les données
    let mut buffer_client = [0u8; 8192];
    let mut buffer_service = [0u8; 8192];

    loop {
        tokio::select! {
            // Client -> Service
            result = client_read.read(&mut buffer_client) => {
                match result? {
                    0 => {
                        println!("[INFO] The client closed the connection for session {}", session_id);
                        break;
                    }
                    n => {
                        // Log des données du client vers le service
                        println!("[INFO] Client -> Service: {} bytes for session {}", n, session_id);
                        //println!("Data: {:?}", &buffer_client[..n]);

                        // Envoie au service
                        match send_tcp_data(session_id, &buffer_client[..n], "natounet.com", &get_resolver()).await {
                            Ok(_) => println!("[INFO] Successfully sent data to service for session {}", session_id),
                            Err(e) => {
                                eprintln!("[ERROR] Failed sending data for session {}: {}", session_id, e);
                                break;
                            }
                        }
                    }
                }
            }

        }
    }

    println!("[INFO] Proxy session {} terminated", session_id);
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
    println!("[INFO] Starting SOCKS5 handshake");
    let mut buf = [0; 1024];

    // Read client's method selection message
    let n = match socket.read(&mut buf).await {
        Ok(n) => {
            println!("[INFO] Read {} bytes during handshake", n);
            n
        }
        Err(e) => {
            println!("[ERROR] Failed to read during handshake: {}", e);
            return Err(e.to_string());
        }
    };

    // Validate SOCKS5 version
    if n < 2 || buf[0] != 0x05 {
        println!("[ERROR] Invalid SOCKS5 format received");
        return Err("[ERROR] Invalid SOCKS5 format".to_string());
    }

    // Check number of authentication methods
    let auth_count = buf[1] as usize;
    if n < 2 + auth_count {
        println!("[ERROR] Invalid SOCKS5 request format");
        return Err("[ERROR] Invalid SOCKS5 request format".to_string());
    }

    // Check for no authentication method (0x00)
    let auth_methods = &buf[2..2 + auth_count];
    if !auth_methods.contains(&0x00) {
        println!("[ERROR] No acceptable authentication methods");
        // Respond with "No acceptable methods"
        match socket.write_all(&[0x05, 0xFF]).await {
            Ok(_) => println!("[INFO] Sent authentication failure response"),
            Err(e) => {
                println!("[ERROR] Failed to send authentication failure: {}", e);
                return Err(e.to_string());
            }
        };
        return Err("[ERROR] No acceptable methods".to_string());
    }

    // Respond with successful no-authentication method
    match socket.write_all(&[0x05, 0x00]).await {
        Ok(_) => {
            println!("[INFO] SOCKS5 handshake completed successfully");
            Ok(())
        }
        Err(e) => {
            println!("[ERROR] Failed to send handshake success: {}", e);
            Err(e.to_string())
        }
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
    println!("[INFO] Starting to handle TCP connection request");
    let mut buf = [0; 1024];

    // Read connection request
    let n = match socket.read(&mut buf).await {
        Ok(n) => {
            println!("[INFO] Read {} bytes from connection request", n);
            n
        }
        Err(e) => {
            println!("[ERROR] Failed to read connection request: {}", e);
            return Err(e);
        }
    };

    if n < 4 {
        println!("[ERROR] Request too short: {} bytes", n);
        return Err(IoError::new(ErrorKind::InvalidData, "Request too short"));
    }

    // Validate SOCKS5 request format
    if buf[0] != 0x05 || buf[1] != 0x01 || buf[2] != 0x00 {
        println!("[ERROR] Invalid SOCKS5 request format");
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "Invalid SOCKS5 request",
        ));
    }

    // Parse destination address based on address type
    let addr_type = buf[3];
    println!("[INFO] Processing address type: {}", addr_type);
    let (dst_addr, total_len) = match addr_type {
        0x01 => {
            // IPv4 address
            if n < 10 {
                println!("[ERROR] Incomplete IPv4 request");
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Incomplete IPv4 request",
                ));
            }
            let ip = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            println!("[INFO] IPv4 address parsed: {}", ip);
            (ip, 8)
        }
        0x03 => {
            // Domain name
            let domain_len = buf[4] as usize;
            if n < domain_len + 7 {
                println!("[ERROR] Incomplete domain request");
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "Incomplete domain request",
                ));
            }
            let domain = match String::from_utf8(buf[5..5 + domain_len].to_vec()) {
                Ok(d) => {
                    println!("[INFO] Domain parsed: {}", d);
                    d
                }
                Err(_) => {
                    println!("[ERROR] Invalid domain encoding");
                    return Err(IoError::new(ErrorKind::InvalidData, "Invalid domain"));
                }
            };
            (domain, domain_len + 5)
        }
        0x04 => {
            println!("[ERROR] IPv6 not supported");
            return Err(IoError::new(ErrorKind::InvalidInput, "IPv6 not supported"));
        }
        _ => {
            println!("[ERROR] Unsupported address type: {}", addr_type);
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "Unsupported address type",
            ));
        }
    };

    // Extract destination port
    let dst_port = u16::from_be_bytes([buf[total_len], buf[total_len + 1]]);
    println!("[INFO] Destination port: {}", dst_port);

    // Resolve domain to IP if needed
    let target_ip = if addr_type == 0x03 {
        match resolve_domain_to_ip(&dst_addr).await {
            Ok(ip) => {
                println!("[INFO] Domain resolved to IP: {}", ip);
                ip
            }
            Err(_) => {
                println!("[ERROR] Domain resolution failed for {}", dst_addr);
                return Err(IoError::new(ErrorKind::Other, "Domain resolution failed"));
            }
        }
    } else {
        dst_addr
    };

    // Establish connection to target service
    let session_id = match connect_to_service(target_ip.as_str(), dst_port).await {
        Ok(session_id) => {
            println!(
                "[INFO] Service connection established with session ID: {}",
                session_id
            );
            session_id
        }
        Err(e) => {
            println!("[ERROR] Service connection failed: {}", e);
            return Err(IoError::new(ErrorKind::ConnectionRefused, e.to_string()));
        }
    };

    // Send successful connection response
    match socket
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
    {
        Ok(_) => println!("[INFO] Sent successful connection response"),
        Err(e) => {
            println!("[ERROR] Failed to send connection response: {}", e);
            return Err(e);
        }
    }

    // Proxy data between client and target service
    if let Err(e) = proxy_bidirectional(socket, session_id).await {
        println!("[ERROR] Proxy operation failed: {}", e);
        return Err(IoError::new(ErrorKind::Other, e.to_string()));
    }

    println!("[INFO] TCP connection handling completed successfully");
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
    println!("[INFO] New client connection accepted");
    // Perform SOCKS5 handshake
    if let Err(e) = handle_socks5_handshake(&mut socket).await {
        eprintln!("[ERROR] SOCKS5 handshake failed: {:?}", e);
        return;
    }

    // Handle TCP connection request
    if let Err(e) = handle_client_tcp_connect(&mut socket).await {
        eprintln!("[ERROR] TCP connection error: {:?}", e);
    }
    println!("[INFO] Client connection handling completed");
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
    println!("[INFO] Starting SOCKS5 proxy server");
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
