use base32::{Alphabet, encode as base32_encode, decode as base32_decode};
use rand::Rng;

/// Divise une séquence d’octets (bytes) en labels de taille maximale 63 caractères
pub fn split_bytes_into_labels(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut labels = Vec::new();
    let mut current_label = Vec::new();

    for &byte in bytes {
        current_label.push(byte);

        if current_label.len() == 63 {
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
            base32_decode(Alphabet::Rfc4648 { padding: false }, &label)
                .expect("Failed to decode base32 label")
        })
        .collect()
}

// Fonction de génération d'un UUID u16 aléatoire
pub fn generate_u16_uuid() -> u16 {
    rand::thread_rng().gen()
}
