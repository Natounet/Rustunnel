use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use rand::Rng;

// Fonction de génération d'un UUID u16 aléatoire
pub fn generate_u16_uuid() -> u16 {
    rand::thread_rng().gen()
}

// 63 chars base32 encoded = 39 bytes
pub fn split_data_into_label_chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut labels = Vec::new();
    let mut current_label = Vec::new();

    for &byte in bytes {
        current_label.push(byte);

        if current_label.len() == 39 {
            labels.push(current_label);
            current_label = Vec::new();
        }
    }

    if !current_label.is_empty() {
        labels.push(current_label);
    }

    labels
}

/// Encode chaque label en base32
pub fn encode_base32(labels: Vec<Vec<u8>>) -> Vec<String> {
    labels
        .into_iter()
        .map(|label| base32_encode(Alphabet::Rfc4648 { padding: false }, &label))
        .collect()
}

/// Décode chaque label de base32 en octets
pub fn decode_base32(labels: Vec<String>) -> Vec<Vec<u8>> {
    labels
        .into_iter()
        .map(|label| {
            base32_decode(Alphabet::Rfc4648 { padding: false }, &label.to_uppercase())
                .unwrap_or_else(|| panic!("Failed to decode base32 label: {}", label))
        })
        .collect()
}

/// Décode une chaine
pub fn decode_base32_fullcontent(labels: String) -> Option<Vec<u8>> {
    match base32::decode(Alphabet::Rfc4648 { padding: false }, &labels.to_uppercase()) {
        Some(bytes) => Some(bytes),
        None => None,
    }
}
