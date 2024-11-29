use crate::utils::*;
use regex::Regex;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;

pub fn get_resolver() -> Resolver {
    Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap()
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

pub fn create_tcp_session(host: &str, port: u16, domain: &str, resolver: &Resolver) -> Result<String, Box<dyn std::error::Error>> {

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
    todo!("TODO: implement query");

    // Make the DNS lookup
    let response = match resolver.lookup(query, trust_dns_resolver::proto::rr::RecordType::TXT) {
        Ok(response) => response,
        Err(e) => return Err(Box::new(e))
    };

    // Parse the response
    if let Some(txt) = response.iter().next() {
        let txt_string = txt.to_string();
        let response_str = String::from_utf8_lossy(txt_string.as_bytes());

        // Check if response indicates failure
        if response_str == "-1" {
            return Err("Failed to create TCP session".into());
        }

        // Return the UID
        Ok(response_str.to_string())
    } else {
        Err("No response received".into())
    }
}
