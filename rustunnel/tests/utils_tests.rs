use rustunnel::utils::{split_bytes_into_labels, encode_base32, decode_base32};
use base32::{Alphabet, encode as base32_encode};

#[test]
fn test_split_bytes_into_labels() {
    let bytes: Vec<u8> = (0..200).collect(); // Tableau de 200 octets

    let result = split_bytes_into_labels(&bytes);

    // Vérifie le nombre de labels
    assert_eq!(result.len(), 4); // 3 labels de 63 octets et 1 de 11 octets
    // Vérifie les tailles des labels
    assert_eq!(result[0].len(), 63);
    assert_eq!(result[1].len(), 63);
    assert_eq!(result[2].len(), 63);
    assert_eq!(result[3].len(), 11);
    // Vérifie que la concaténation des labels correspond aux octets originaux
    assert_eq!(result.concat(), bytes);
}

#[test]
fn test_encode_base32() {
    let labels = vec![
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
    ];

    let encoded_labels = encode_base32(labels.clone());

    // Vérifie que chaque label est encodé en base32
    assert_eq!(encoded_labels.len(), 2);
    assert!(encoded_labels[0].chars().all(|c| c.is_ascii_alphanumeric()));
    assert!(encoded_labels[1].chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn test_decode_base32() {
    let labels = vec![
        base32_encode(Alphabet::Rfc4648 { padding: false }, &vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        base32_encode(Alphabet::Rfc4648 { padding: false }, &vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19]),
    ];

    let decoded_labels = decode_base32(labels.clone());

    // Vérifie que les labels sont correctement décodés
    assert_eq!(decoded_labels.len(), 2);
    assert_eq!(decoded_labels[0], vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(decoded_labels[1], vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
}

#[test]
fn test_encode_decode_cycle() {
    let labels = vec![
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
    ];

    let encoded_labels = encode_base32(labels.clone());
    let decoded_labels = decode_base32(encoded_labels);

    // Vérifie que l'encodage et le décodage sont cohérents
    assert_eq!(decoded_labels, labels);
}

#[test]
fn test_full_pipeline() {
    let bytes: Vec<u8> = (0..200).collect(); // Tableau de 200 octets

    let labels = split_bytes_into_labels(&bytes);
    let encoded_labels = encode_base32(labels.clone());
    let decoded_labels = decode_base32(encoded_labels);
    let reassembled_bytes: Vec<u8> = decoded_labels.concat();

    // Vérifie que les données finales sont identiques aux données d'origine
    assert_eq!(reassembled_bytes, bytes);
}
