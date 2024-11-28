// DNS labels = max 63 chars.
// 63 base62 chars = 378 bits.
use base_62;

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

pub fn encode_base62(labels: Vec<Vec<u8>>) -> Vec<String> {
    let mut encoded_labels = Vec::new();

    for label in labels {
        encoded_labels.push(base_62::encode(&label));
    }

    encoded_labels
}

pub fn decode_base62(labels: Vec<String>) -> Vec<Vec<u8>> {
    let mut decoded_labels = Vec::new();

    for label in labels {
        decoded_labels.push(base_62::decode(&label).unwrap());
    }

    decoded_labels
}
