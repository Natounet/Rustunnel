use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use rand::Rng;

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
            base32_decode(Alphabet::Rfc4648 { padding: false }, &label)
                .expect("Failed to decode base32 label")
        })
        .collect()
}

// Fonction de génération d'un UUID u16 aléatoire
pub fn generate_u16_uuid() -> u16 {
    rand::thread_rng().gen()
}

/* ====================== TESTS ====================== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_length_limit() {
        let test_sizes: Vec<usize> = (0..100).map(|_| rand::random::<usize>() % 10000).collect();

        for size in test_sizes {
            let random_bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
            let encoded = encode_base32(split_data_into_label_chunks(&random_bytes));
            assert!(
                encoded.iter().all(|label| label.len() <= 63),
                "A label in {:?}  exceeds DNS limit of 63 chars (input size: {})",
                encoded,
                size
            );
        }
    }
}
