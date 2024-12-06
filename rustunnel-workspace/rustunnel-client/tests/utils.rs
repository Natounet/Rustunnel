use rustunnel_lib::utils::*;

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

    #[test]
    fn test_vec() {
        let v: Vec<Vec<u8>> = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        assert_eq!(
            v.into_iter().flatten().collect::<Vec<u8>>(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn test_vec_b32() {
        let v: Vec<String> = vec![
            "NITWC2LNMU".to_string(),
            "NRSXG".to_string(),
            "OBXW23LFOM".to_string(),
        ];
        let decoded = decode_base32(v.clone());

        let mut expected = decoded[0].clone();
        expected.extend(&decoded[1]);
        expected.extend(&decoded[2]);

        let result = decode_base32(v).into_iter().flatten().collect::<Vec<u8>>();

        assert_eq!(result, expected);
    }
}
