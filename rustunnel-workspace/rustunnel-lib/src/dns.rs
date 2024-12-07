use crate::utils::*;
use hickory_resolver::config::*;
use hickory_resolver::TokioAsyncResolver;
use regex::Regex;

pub fn get_resolver() -> TokioAsyncResolver {
    TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            vec![NameServerConfig {
                socket_addr: "127.0.0.1:1053".parse().unwrap(),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            }],
        ),
        ResolverOpts::default(),
    )
}

pub fn is_valid_fqdn(domain: &str) -> bool {
    const MAX_DOMAIN_LENGTH: usize = 255;
    const MAX_LABEL_LENGTH: usize = 63;

    // Expression régulière pour un label DNS
    let label_regex = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$").unwrap();

    // Vérifie la longueur totale du domaine
    if domain.len() > MAX_DOMAIN_LENGTH || domain.trim().is_empty() {
        return false;
    }

    // Séparer les labels par les points
    let labels: Vec<&str> = domain.split('.').collect();

    // Vérifier le TLD (dernier label) : il ne doit pas être numérique
    let tld = labels.last().unwrap_or(&"");
    if tld.chars().all(char::is_numeric) {
        return false; // TLD entièrement numérique
    }

    // Vérifier chaque label individuellement
    for label in labels {
        if label.len() > MAX_LABEL_LENGTH || !label_regex.is_match(label) {
            return false; // Label trop long ou invalide
        }
    }

    true
}

pub fn verify_host(host: &str) -> bool {
    // Try to parse as IPv4
    if host.split('.').count() == 4 {
        if let Ok(_) = host.parse::<std::net::Ipv4Addr>() {
            return true;
        }
    }

    // If not IPv4, check if valid FQDN
    is_valid_fqdn(host)
}

pub async fn create_tcp_session(
    host: &str,
    port: u16,
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<u16, String> {
    println!("Host: {}", host);
    println!("Port: {}", port);
    println!("Domain: {}", domain);
    // Validate host
    if !verify_host(host) {
        return Err("Invalid host".into());
    }

    // Encode host in base32
    let host_bytes: Vec<Vec<u8>> = vec![host.as_bytes().to_vec()];

    let host_b64 = encode_base32(host_bytes).pop().unwrap();

    // Create the DNS query
    let query = format!("CREATE.{}.{}.{}", host_b64, port, domain);

    // Check if query is valid FQDN
    if !is_valid_fqdn(&query) {
        eprintln!("About to fail with query: {}", query);
        return Err("Host is too long".into());
    }

    println!("Query: {}", query);

    // Make the DNS lookup
    let response = match resolver
        .lookup(query, hickory_resolver::proto::rr::RecordType::TXT)
        .await
    {
        Ok(response) => response,
        Err(_) => return Err(format!("ERROR : Failed to resolve the domain : {}", domain)),
    };

    // Parse the response
    if let Some(txt) = response.iter().next() {
        let txt_string = txt.to_string();
        let response_str = String::from_utf8_lossy(txt_string.as_bytes());

        // Check if response indicates failure
        if response_str == "-1" {
            return Err("ERROR : Failed to create the TCP session".into());
        }

        // Return the UID
        Ok(response_str.parse::<u16>().unwrap())
    } else {
        Err("ERROR : No response received from the DNS server".into())
    }
}

pub async fn send_request(
    query: &String,
    resolver: &TokioAsyncResolver,
) -> Result<String, Box<dyn std::error::Error>> {
    // Check if query is valid FQDN
    if !is_valid_fqdn(&query) {
        eprintln!("Invalid query: {}", query);
        return Err("Invalid query".into());
    }
    println!("Sending query: {}", query);
    // Make the DNS lookup
    let response = match resolver
        .lookup(query, hickory_resolver::proto::rr::RecordType::TXT)
        .await
    {
        Ok(response) => response,
        Err(e) => return Err(Box::new(e)),
    };
    // Parse the response
    if let Some(txt) = response.iter().next() {
        let txt_string = txt.to_string();
        let response_str = String::from_utf8_lossy(txt_string.as_bytes());
        Ok(response_str.to_string())
    } else {
        Err("No response received".into())
    }
}
/// Sends TCP data through DNS tunneling by encoding it in DNS queries
///
/// # Format
///
/// Data Query:
/// ```text
/// [DATA_B64].[SEQ].[MAXSEQ].[UID].[DOMAIN]
/// ```
/// - DATA_B64: Base32 encoded data fragment
/// - SEQ: Sequence number (offset)
/// - MAXSEQ: Total number of data fragments
/// - UID: Unique TCP session identifier
/// - DOMAIN: Target domain name
///
/// # Arguments
///
/// * `session_id` - Unique identifier for the TCP session
/// * `tcp_bytes` - Raw TCP data to be sent
/// * `domain` - Target domain name for DNS tunneling
///
/// # Panics
///
/// Will panic if any generated DNS query exceeds 254 characters
pub async fn send_tcp_data(
    session_id: u16,
    tcp_bytes: &[u8],
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<(), String> {
    // Split TCP data into chunks and encode as base32
    let data_chunks = split_data_into_label_chunks(tcp_bytes);
    let data_b64 = encode_base32(data_chunks);
    // TODO : For the moment, only one label is used per query
    // Generate DNS queries for each data chunk
    let queries: Vec<String> = data_b64
        .iter()
        .enumerate()
        .map(|(i, label)| {
            let query = format!(
                "data.{}.{}.{}.{}.{}",
                label,
                i,
                data_b64.len(),
                session_id,
                domain
            );
            if query.len() > 254 {
                panic!("DNS query too long: {} chars", query.len());
            }
            query
        })
        .collect();
    // TODO ; Make the requests in parallel
    for query in queries {
        let mut timeout = 0;
        loop {
            match send_request(&query, resolver).await {
                Ok(_) => break, // Success, move to next query
                Err(e) => {
                    if timeout >= 10 {
                        return Err("ERROR : Failed to contact the DNS server for 10 times when trying to send the queries".to_string());
                    }
                    timeout += 1;
                    eprintln!("Error sending request: {}, retrying...", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
            }
        }
    }
    Ok(())
}
/// Retrieve the response data from the server
/// Query :RESPONSE.UID.DOMAIN
/// Response : Base32 encoded data or EOF
pub async fn retrieve_response(
    session_id: u16,
    domain: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Vec<u8>, String> {
    let mut b32_encoded_fragments: Vec<String> = vec![];
    let query: String = format!("RESPONSE.{}.{}", session_id, domain);
    loop {
        let i: usize = 0;
        match send_request(&query, resolver).await {
            Ok(response) => match response {
                ref eol if eol == "EOL" => break,
                b32_content => b32_encoded_fragments.push(b32_content),
            },
            // Retry to contact the server 10 times
            Err(_) => {
                if i == 10 {
                    break;
                } else {
                    return Err(
                        "ERROR : Failed to contact the DNS server for 10 times when trying to get responses.".to_string()
                    );
                }
            }
        }
    }
    Ok(decode_base32(b32_encoded_fragments)
        .into_iter()
        .flatten()
        .collect())
}
